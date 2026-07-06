package main

/*
#include <stdlib.h>
*/
import "C"
import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/l7-shred/core/internal/engine"
	"github.com/l7-shred/core/internal/shred"
	"github.com/l7-shred/core/internal/transport"
	"github.com/l7-shred/core/internal/tun"
)

var (
	clientInstance  *engine.Client
	clientMutex     sync.Mutex
	isRunning       bool
	stopChan        chan struct{}
	currentServerIP string
	lastStats       map[string]interface{}
	tunDevice       *tun.TunDevice
	tunReaderDone   chan struct{}
)

type FlutterConfig struct {
	Server      string   `json:"server"`
	SecretKey   string   `json:"secret_key"`
	Cipher      string   `json:"cipher"`
	MTU         int      `json:"mtu"`
	Modes       []string `json:"modes"`
	SplitTunnel bool     `json:"split_tunnel"`
}

type VPNStatus struct {
	Status      string `json:"status"`
	ClientIP    string `json:"client_ip"`
	ServerIP    string `json:"server_ip"`
	Ping        int    `json:"ping"`
	SpeedIn     int    `json:"speed_in"`
	SpeedOut    int    `json:"speed_out"`
	BytesIn     int64  `json:"bytes_in"`
	BytesOut    int64  `json:"bytes_out"`
	Mode        string `json:"mode"`
	ConnectedAt string `json:"connected_at"`
}

func cleanupResources() {
	if stopChan != nil {
		close(stopChan)
		stopChan = nil
	}
	if tunDevice != nil {
		tunDevice.Close()
		tunDevice = nil
	}
	if tunReaderDone != nil {
		select {
		case <-tunReaderDone:
		default:
		}
		tunReaderDone = nil
	}
	if clientInstance != nil {
		clientInstance.Stop()
		clientInstance = nil
	}
	isRunning = false
}

//export SetTunFileDescriptor
func SetTunFileDescriptor(fd C.int) *C.char {
	// Этот метод используется только на Android
	// На Windows TUN создается внутри StartVPN
	// Возвращаем успешный ответ для совместимости
	return C.CString(`{"status":"ok"}`)
}

//export StartVPN
func StartVPN(configJSON *C.char) *C.char {
	clientMutex.Lock()
	defer clientMutex.Unlock()

	if isRunning {
		return C.CString(`{"status":"already_connected"}`)
	}

	configStr := C.GoString(configJSON)

	var flutterConfig FlutterConfig
	if err := json.Unmarshal([]byte(configStr), &flutterConfig); err != nil {
		return C.CString(`{"status":"error","message":"` + err.Error() + `"}`)
	}

	if flutterConfig.Server == "" {
		return C.CString(`{"status":"error","message":"server address required"}`)
	}

	if flutterConfig.SecretKey == "" {
		return C.CString(`{"status":"error","message":"secret key required"}`)
	}

	if flutterConfig.MTU == 0 {
		flutterConfig.MTU = 1200
	}

	if flutterConfig.Cipher == "" {
		flutterConfig.Cipher = "aes-256-gcm"
	}

	currentServerIP = flutterConfig.Server

	modes := make([]shred.ProtocolMode, 0, len(flutterConfig.Modes))
	if len(flutterConfig.Modes) == 0 {
		modes = []shred.ProtocolMode{shred.ModeVK}
	} else {
		for _, m := range flutterConfig.Modes {
			switch m {
			case "vk":
				modes = append(modes, shred.ModeVK)
			case "rutube":
				modes = append(modes, shred.ModeRuTube)
			case "yandex":
				modes = append(modes, shred.ModeYandex)
			case "ozon":
				modes = append(modes, shred.ModeOzon)
			case "wildberries":
				modes = append(modes, shred.ModeWildberries)
			case "sberid":
				modes = append(modes, shred.ModeSberID)
			case "gosuslugi":
				modes = append(modes, shred.ModeGosuslugi)
			case "webrtc":
				modes = append(modes, shred.ModeWebRTC)
			case "quic":
				modes = append(modes, shred.ModeQUIC)
			case "tls":
				modes = append(modes, shred.ModeTLS)
			default:
				modes = append(modes, shred.ModeVK)
			}
		}
	}

	if runtime.GOOS == "windows" {
		exePath, err := os.Executable()
		if err == nil {
			exeDir := filepath.Dir(exePath)
			os.Setenv("PATH", os.Getenv("PATH")+";"+exeDir)
			log.Printf("Added %s to PATH for wintun.dll", exeDir)
		}
		workDir, err := os.Getwd()
		if err == nil {
			os.Setenv("PATH", os.Getenv("PATH")+";"+workDir)
			log.Printf("Added %s to PATH for wintun.dll", workDir)
		}
	}

	clientConfig := &engine.ClientConfig{
		TransportConfig: &transport.Config{
			ServerAddr:      flutterConfig.Server,
			Protocol:        "udp",
			ReliableUDP:     true,
			SecretKey:       flutterConfig.SecretKey,
			MTU:             flutterConfig.MTU,
			Cipher:          flutterConfig.Cipher,
			DNSServer:       "8.8.8.8",
			DNSOverHTTPS:    true,
			TLSSNI:          "www.google.com",
			TLSCertFetch:    true,
			FragmentEnabled: true,
			FragmentMin:     32,
			FragmentMax:     288,
		},
		AuthKey:                []byte(flutterConfig.SecretKey),
		Cipher:                 flutterConfig.Cipher,
		SwitchInterval:         86400 * time.Second,
		Modes:                  modes,
		HandshakeTimeout:       10 * time.Second,
		EnableReplayProtection: true,
		DNSServer:              "8.8.8.8",
		DNSOverHTTPS:           true,
		TLSSNI:                 "www.google.com",
		TLSCertFetch:           true,
		FragmentEnabled:        true,
		FragmentMin:            32,
		FragmentMax:            288,
		BackgroundEnabled:      true,
		BackgroundInterval:     30 * time.Second,
		ReliableUDP:            true,
		SplitTunnel:            flutterConfig.SplitTunnel,
		TUNInterface:           "l7shred",
	}

	client := engine.NewClient(clientConfig)
	if client == nil {
		return C.CString(`{"status":"error","message":"failed to create client"}`)
	}

	// TUN только на Windows
	if runtime.GOOS == "windows" {
		log.Println("Creating TUN device...")
		tunDev, err := tun.NewTunDevice()
		if err != nil {
			return C.CString(`{"status":"error","message":"` + err.Error() + `"}`)
		}
		tunDevice = tunDev
		if err := tunDev.SetupIP("10.0.0.2"); err != nil {
			tunDev.Close()
			tunDevice = nil
			cleanupResources()
			return C.CString(`{"status":"error","message":"` + err.Error() + `"}`)
		}
		log.Printf("TUN device created, IP: 10.0.0.2")
	}

	if err := client.Start(); err != nil {
		if tunDevice != nil {
			tunDevice.Close()
			tunDevice = nil
		}
		cleanupResources()
		return C.CString(`{"status":"error","message":"` + err.Error() + `"}`)
	}

	timeout := time.Now().Add(10 * time.Second)
	for !client.IsConnected() {
		if time.Now().After(timeout) {
			client.Stop()
			if tunDevice != nil {
				tunDevice.Close()
				tunDevice = nil
			}
			cleanupResources()
			return C.CString(`{"status":"error","message":"connection timeout"}`)
		}
		time.Sleep(100 * time.Millisecond)
	}

	log.Println("Client connected to server")

	stopChan = make(chan struct{})

	if runtime.GOOS == "windows" && tunDevice != nil {
		tunReaderDone = make(chan struct{})
		go func() {
			defer close(tunReaderDone)
			log.Println("TUN reader: started")
			for {
				select {
				case <-stopChan:
					log.Println("TUN reader: stop signal received")
					return
				default:
				}
				data, err := tunDevice.Read()
				if err != nil {
					log.Printf("TUN read error: %v", err)
					return
				}
				if len(data) == 0 {
					continue
				}
				if client.IsConnected() {
					client.Send(data)
				}
			}
		}()
	}

	client.SetOnPacket(func(data []byte) {
		if tunDevice != nil {
			tunDevice.Write(data)
		}
	})

	clientInstance = client
	isRunning = true

	return C.CString(`{"status":"connected"}`)
}

//export StopVPN
func StopVPN() *C.char {
	log.Println("StopVPN: called")

	clientMutex.Lock()
	defer clientMutex.Unlock()

	if !isRunning {
		log.Println("StopVPN: already stopped")
		return C.CString(`{"status":"disconnected"}`)
	}

	log.Println("StopVPN: stopping VPN...")

	if stopChan != nil {
		log.Println("StopVPN: closing stopChan")
		close(stopChan)
		stopChan = nil
	}

	if tunDevice != nil {
		log.Println("StopVPN: closing TUN device...")
		tunDevice.Close()
		tunDevice = nil
	}

	if tunReaderDone != nil {
		log.Println("StopVPN: waiting for TUN reader...")
		<-tunReaderDone
		log.Println("StopVPN: TUN reader finished")
		tunReaderDone = nil
	}

	if clientInstance != nil {
		log.Println("StopVPN: stopping client...")
		clientInstance.Stop()
		clientInstance = nil
	}

	isRunning = false
	log.Println("StopVPN: VPN stopped successfully")

	return C.CString(`{"status":"disconnected"}`)
}

//export GetStats
func GetStats() *C.char {
	clientMutex.Lock()
	defer clientMutex.Unlock()

	if !isRunning || clientInstance == nil {
		status := VPNStatus{
			Status:      "disconnected",
			ClientIP:    "",
			ServerIP:    "",
			Ping:        0,
			SpeedIn:     0,
			SpeedOut:    0,
			BytesIn:     0,
			BytesOut:    0,
			Mode:        "",
			ConnectedAt: "",
		}
		jsonData, _ := json.Marshal(status)
		return C.CString(string(jsonData))
	}

	stats := clientInstance.GetStats()
	lastStats = stats

	status := VPNStatus{
		Status:      "connected",
		ClientIP:    "10.0.0.2",
		ServerIP:    currentServerIP,
		Ping:        0,
		SpeedIn:     0,
		SpeedOut:    0,
		BytesIn:     0,
		BytesOut:    0,
		Mode:        "",
		ConnectedAt: time.Now().Format(time.RFC3339),
	}

	if pingVal, ok := stats["ping_ms"]; ok {
		if pingFloat, ok := pingVal.(float64); ok {
			status.Ping = int(pingFloat)
		}
	}

	if speedInVal, ok := stats["speed_in_mbps"]; ok {
		if speedInFloat, ok := speedInVal.(float64); ok {
			status.SpeedIn = int(speedInFloat)
		}
	}

	if speedOutVal, ok := stats["speed_out_mbps"]; ok {
		if speedOutFloat, ok := speedOutVal.(float64); ok {
			status.SpeedOut = int(speedOutFloat)
		}
	}

	if bytesInVal, ok := stats["bytes_recv"]; ok {
		switch v := bytesInVal.(type) {
		case uint64:
			status.BytesIn = int64(v)
		case int64:
			status.BytesIn = v
		case float64:
			status.BytesIn = int64(v)
		}
	}

	if bytesOutVal, ok := stats["bytes_sent"]; ok {
		switch v := bytesOutVal.(type) {
		case uint64:
			status.BytesOut = int64(v)
		case int64:
			status.BytesOut = v
		case float64:
			status.BytesOut = int64(v)
		}
	}

	if modeVal, ok := stats["current_mode"]; ok {
		if modeStr, ok := modeVal.(string); ok {
			status.Mode = modeStr
		}
	}

	jsonData, _ := json.Marshal(status)
	return C.CString(string(jsonData))
}

//export SetConfig
func SetConfig(configJSON *C.char) *C.char {
	return C.CString(`{"status":"ok"}`)
}

//export WriteTUN
func WriteTUN(data []byte) {
	if clientInstance != nil && clientInstance.IsConnected() {
		clientInstance.Send(data)
	}
}

func main() {
	log.SetOutput(os.Stdout)
}