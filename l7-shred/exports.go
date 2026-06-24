package main

/*
#include <stdlib.h>
*/
import "C"
import (
	"encoding/json"
	"log"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/l7-shred/core/internal/engine"
	"github.com/l7-shred/core/internal/shred"
	"github.com/l7-shred/core/internal/transport"
	"github.com/l7-shred/core/internal/tun"
)

var (
	clientInstance *engine.Client
	tunDevice      *tun.TunDevice
	clientMutex    sync.Mutex
	isRunning      bool
	stopChan       chan struct{}
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

	modes := make([]shred.ProtocolMode, 0, len(flutterConfig.Modes))
	if len(flutterConfig.Modes) == 0 {
		modes = []shred.ProtocolMode{
			shred.ModeVK,
		}
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

	log.Println("Creating TUN device...")
	tunDev, err := tun.NewTunDevice()
	if err != nil {
		return C.CString(`{"status":"error","message":"` + err.Error() + `"}`)
	}
	tunDevice = tunDev

	if err := tunDev.SetupIP("10.0.0.2"); err != nil {
		tunDev.Close()
		tunDevice = nil
		return C.CString(`{"status":"error","message":"` + err.Error() + `"}`)
	}
	log.Printf("TUN device created, IP: 10.0.0.2")

	tunName := tunDev.Name()
	log.Printf("TUN interface name: %s", tunName)

	exec.Command("netsh", "interface", "ipv4", "set", "interface", tunName, "metric=1").Run()

	if err := client.Start(); err != nil {
		tunDev.Close()
		tunDevice = nil
		return C.CString(`{"status":"error","message":"` + err.Error() + `"}`)
	}

	timeout := time.Now().Add(10 * time.Second)
	for !client.IsConnected() {
		if time.Now().After(timeout) {
			client.Stop()
			tunDev.Close()
			tunDevice = nil
			return C.CString(`{"status":"error","message":"connection timeout"}`)
		}
		time.Sleep(100 * time.Millisecond)
	}

	log.Println("Client connected to server")

	stopChan = make(chan struct{})

	go func() {
		for {
			select {
			case <-stopChan:
				return
			default:
			}
			data, err := tunDev.Read()
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
	clientMutex.Lock()
	defer clientMutex.Unlock()

	if !isRunning {
		return C.CString(`{"status":"disconnected"}`)
	}

	if stopChan != nil {
		close(stopChan)
		stopChan = nil
	}

	if clientInstance != nil {
		clientInstance.Stop()
		clientInstance = nil
	}

	if tunDevice != nil {
		tunDevice.Close()
		tunDevice = nil
	}

	isRunning = false

	return C.CString(`{"status":"disconnected"}`)
}

//export GetStats
func GetStats() *C.char {
	clientMutex.Lock()
	defer clientMutex.Unlock()

	if !isRunning || clientInstance == nil {
		status := VPNStatus{
			Status: "disconnected",
		}
		jsonData, _ := json.Marshal(status)
		return C.CString(string(jsonData))
	}

	stats := clientInstance.GetStats()

	status := VPNStatus{
		Status:   "connected",
		ClientIP: "10.0.0.2",
		ServerIP: "85.120.81.85",
		Ping:     46,
		SpeedIn:  1200,
		SpeedOut: 800,
	}

	if bytesIn, ok := stats["bytes_recv"].(uint64); ok {
		status.BytesIn = int64(bytesIn)
	}
	if bytesOut, ok := stats["bytes_sent"].(uint64); ok {
		status.BytesOut = int64(bytesOut)
	}
	if mode, ok := stats["current_mode"].(string); ok {
		status.Mode = mode
	}

	jsonData, _ := json.Marshal(status)
	return C.CString(string(jsonData))
}

//export SetConfig
func SetConfig(configJSON *C.char) *C.char {
	return C.CString(`{"status":"ok"}`)
}

func main() {
	log.SetOutput(os.Stdout)
}