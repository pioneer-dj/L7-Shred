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
	clientInstance   *engine.Client
	clientMutex      sync.Mutex
	isRunning        bool
	isStopping       bool
	stopChan         chan struct{}
	currentServerIP  string
	lastStats        map[string]interface{}
	tunDevice        *tun.TunDevice
	tunReaderDone    chan struct{}
	onPacketCallback func([]byte)
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

func init() {
	logFile, err := os.OpenFile("vpn.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err == nil {
		log.SetOutput(logFile)
	} else {
		log.SetOutput(os.Stdout)
	}
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

//export SetOnPacketCallback
func SetOnPacketCallback(callback func([]byte)) {
	onPacketCallback = callback
}

//export SetTunFileDescriptor
func SetTunFileDescriptor(fd C.int) *C.char {
	log.Printf("SetTunFileDescriptor: fd=%d", fd)

	if tunDevice == nil {
		tunDev, err := tun.NewTunDevice()
		if err != nil {
			return C.CString(`{"status":"error","message":"` + err.Error() + `"}`)
		}
		tunDevice = tunDev
	}

	if err := tunDevice.SetFD(int(fd)); err != nil {
		return C.CString(`{"status":"error","message":"` + err.Error() + `"}`)
	}

	log.Printf("SetTunFileDescriptor: FD set successfully")

	if runtime.GOOS == "android" {
		go startAndroidTunReader()
	}

	return C.CString(`{"status":"ok"}`)
}

func startAndroidTunReader() {
	log.Println("Android TUN reader: started")

	for i := 0; i < 30; i++ {
		if clientInstance != nil && clientInstance.IsConnected() {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	if clientInstance == nil || !clientInstance.IsConnected() {
		log.Println("Android TUN reader: client not connected")
		return
	}

	for {
		select {
		case <-stopChan:
			log.Println("Android TUN reader: stop signal received")
			return
		default:
		}

		if tunDevice == nil {
			time.Sleep(100 * time.Millisecond)
			continue
		}

		data, err := tunDevice.Read()
		if err != nil {
			log.Printf("Android TUN read error: %v", err)
			return
		}
		if len(data) == 0 {
			continue
		}
		if clientInstance.IsConnected() {
			clientInstance.Send(data)
		}
	}
}

//export StartVPN
func StartVPN(configJSON *C.char) *C.char {
	log.Println("========================================")
	log.Println("StartVPN: called")
	log.Println("========================================")

	clientMutex.Lock()
	defer clientMutex.Unlock()

	if isRunning {
		log.Println("StartVPN: already running")
		return C.CString(`{"status":"already_connected"}`)
	}

	if isStopping {
		log.Println("StartVPN: stopping in progress, wait...")
		clientMutex.Unlock()
		time.Sleep(500 * time.Millisecond)
		clientMutex.Lock()
		if isStopping {
			log.Println("StartVPN: stop still in progress")
			return C.CString(`{"status":"error","message":"stop in progress"}`)
		}
	}

	configStr := C.GoString(configJSON)
	log.Printf("StartVPN: config length=%d", len(configStr))

	var flutterConfig FlutterConfig
	if err := json.Unmarshal([]byte(configStr), &flutterConfig); err != nil {
		log.Printf("StartVPN: json parse error: %v", err)
		return C.CString(`{"status":"error","message":"` + err.Error() + `"}`)
	}

	log.Printf("StartVPN: server=%s, modes=%v", flutterConfig.Server, flutterConfig.Modes)

	if flutterConfig.Server == "" {
		log.Println("StartVPN: server address required")
		return C.CString(`{"status":"error","message":"server address required"}`)
	}

	if flutterConfig.SecretKey == "" {
		log.Println("StartVPN: secret key required")
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
	log.Printf("StartVPN: modes=%v", modes)

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

	log.Println("StartVPN: creating client...")
	client := engine.NewClient(clientConfig)
	if client == nil {
		log.Println("StartVPN: failed to create client")
		return C.CString(`{"status":"error","message":"failed to create client"}`)
	}

	if runtime.GOOS == "windows" {
		log.Println("StartVPN: creating TUN device...")
		tunDev, err := tun.NewTunDevice()
		if err != nil {
			log.Printf("StartVPN: TUN creation error: %v", err)
			return C.CString(`{"status":"error","message":"` + err.Error() + `"}`)
		}
		tunDevice = tunDev
		if err := tunDev.SetupIP("10.0.0.2"); err != nil {
			log.Printf("StartVPN: TUN IP setup error: %v", err)
			tunDev.Close()
			tunDevice = nil
			cleanupResources()
			return C.CString(`{"status":"error","message":"` + err.Error() + `"}`)
		}
		log.Println("StartVPN: TUN device created, IP: 10.0.0.2")
	}

	log.Println("StartVPN: starting client...")
	if err := client.Start(); err != nil {
		log.Printf("StartVPN: client start error: %v", err)
		if tunDevice != nil {
			tunDevice.Close()
			tunDevice = nil
		}
		cleanupResources()
		return C.CString(`{"status":"error","message":"` + err.Error() + `"}`)
	}

	timeout := time.Now().Add(10 * time.Second)
	log.Println("StartVPN: waiting for connection...")
	for !client.IsConnected() {
		if time.Now().After(timeout) {
			log.Println("StartVPN: connection timeout")
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

	log.Println("StartVPN: client connected to server")

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
		} else if runtime.GOOS == "android" && onPacketCallback != nil {
			onPacketCallback(data)
		}
	})

	clientInstance = client
	isRunning = true

	log.Println("StartVPN: SUCCESS")
	log.Println("========================================")
	return C.CString(`{"status":"connected"}`)
}

//export StopVPN
func StopVPN() *C.char {
	log.Println("StopVPN: called")

	clientMutex.Lock()

	if !isRunning {
		clientMutex.Unlock()
		log.Println("StopVPN: already stopped")
		return C.CString(`{"status":"disconnected"}`)
	}

	if isStopping {
		clientMutex.Unlock()
		log.Println("StopVPN: already stopping")
		return C.CString(`{"status":"disconnected"}`)
	}

	isStopping = true
	clientMutex.Unlock()

	log.Println("StopVPN: stopping VPN...")

	if clientInstance != nil && clientInstance.IsConnected() {
		log.Println("StopVPN: sending FIN handshake to server...")
		conn := clientInstance.GetConn()
		if conn != nil {
			session := clientInstance.GetSession()
			if session != nil {
				fin := shred.NewHandshake(
					shred.HandshakeFin,
					session.MaskConfig.SwitchInterval,
					session.MaskConfig.Modes,
					session.MaskConfig.CurrentMode,
					uint64(session.LocalMixer.GetCurrentMode()),
				)
				finData := fin.Encode()

				authKey := clientInstance.GetAuthKey()
				if len(authKey) > 0 {
					handshakeMgr := shred.NewHandshakeManager(authKey, 5*time.Second)
					signature := handshakeMgr.Sign(finData)
					packet := append(finData, signature...)

					for i := 0; i < 3; i++ {
						if _, err := conn.Write(packet); err != nil {
							log.Printf("StopVPN: FIN write error (attempt %d): %v", i+1, err)
						} else {
							log.Printf("StopVPN: FIN sent (attempt %d)", i+1)
						}
						time.Sleep(50 * time.Millisecond)
					}
				}
			}
		}
	}

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

	clientMutex.Lock()
	isStopping = false
	isRunning = false
	clientMutex.Unlock()

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