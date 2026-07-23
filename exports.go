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
	netStackInstance *tun.NetStack
)

type FlutterConfig struct {
	Server      string   `json:"server"`
	SecretKey   string   `json:"secret_key"`
	Cipher      string   `json:"cipher"`
	MTU         int      `json:"mtu"`
	Modes       []string `json:"modes"`
	SplitTunnel bool     `json:"split_tunnel"`
	Mode        string   `json:"mode"`
	Protocol    string   `json:"protocol"`
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
		log.Println("=== LOG INITIALIZED ===")
	} else {
		log.SetOutput(os.Stdout)
		log.Println("=== LOG INITIALIZED (stdout) ===")
	}
}

func cleanupResources() {
	log.Println("[CLEANUP] cleanupResources: START")
	if stopChan != nil {
		log.Println("[CLEANUP] closing stopChan")
		close(stopChan)
		stopChan = nil
	}
	if netStackInstance != nil {
		log.Println("[CLEANUP] closing netStack")
		netStackInstance.Close()
		netStackInstance = nil
	}
	if tunDevice != nil {
		log.Println("[CLEANUP] closing tunDevice")
		tunDevice.Close()
		tunDevice = nil
	}
	if tunReaderDone != nil {
		select {
		case <-tunReaderDone:
			log.Println("[CLEANUP] tunReaderDone already closed")
		default:
			log.Println("[CLEANUP] waiting for tunReaderDone")
		}
		tunReaderDone = nil
	}
	if clientInstance != nil {
		log.Println("[CLEANUP] stopping clientInstance")
		clientInstance.Stop()
		clientInstance = nil
	}
	isRunning = false
	log.Println("[CLEANUP] cleanupResources: END")
}

//export SetOnPacketCallback
func SetOnPacketCallback(callback func([]byte)) {
	log.Println("[EXPORT] SetOnPacketCallback called")
	onPacketCallback = callback
	log.Println("[EXPORT] SetOnPacketCallback done")
}

//export SetTunFileDescriptor
func SetTunFileDescriptor(fd C.int) *C.char {
	log.Printf("[EXPORT] SetTunFileDescriptor: START fd=%d", fd)

	if tunDevice == nil {
		log.Println("[EXPORT] SetTunFileDescriptor: tunDevice is nil, creating new")
		tunDev, err := tun.NewTunDevice()
		if err != nil {
			log.Printf("[EXPORT] SetTunFileDescriptor: ERROR creating TUN: %v", err)
			return C.CString(`{"status":"error","message":"` + err.Error() + `"}`)
		}
		tunDevice = tunDev
		log.Println("[EXPORT] SetTunFileDescriptor: tunDevice created successfully")
	} else {
		log.Println("[EXPORT] SetTunFileDescriptor: tunDevice already exists")
	}

	if runtime.GOOS == "android" {
		log.Printf("[EXPORT] SetTunFileDescriptor: setting FD for Android: %d", fd)
		if err := tunDevice.SetFD(int(fd)); err != nil {
			log.Printf("[EXPORT] SetTunFileDescriptor: ERROR setting FD: %v", err)
			return C.CString(`{"status":"error","message":"` + err.Error() + `"}`)
		}
		log.Printf("[EXPORT] SetTunFileDescriptor: FD set successfully")
		if tunDevice != nil {
			log.Println("[EXPORT] SetTunFileDescriptor: starting Android TUN reader")
			go startAndroidTunReader()
		} else {
			log.Println("[EXPORT] SetTunFileDescriptor: tunDevice is nil, cannot start reader")
		}
	} else {
		log.Printf("[EXPORT] SetTunFileDescriptor: SetFD not needed on %s", runtime.GOOS)
	}

	log.Println("[EXPORT] SetTunFileDescriptor: END returning ok")
	return C.CString(`{"status":"ok"}`)
}

func startAndroidTunReader() {
	log.Println("[TUN-READER] Android TUN reader: START")
	if tunDevice == nil {
		log.Println("[TUN-READER] Android TUN reader: tunDevice is nil, exiting")
		return
	}
	log.Println("[TUN-READER] Android TUN reader: started, waiting for client...")

	for i := 0; i < 30; i++ {
		if clientInstance != nil && clientInstance.IsConnected() {
			log.Printf("[TUN-READER] Android TUN reader: client connected after %d attempts", i+1)
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	if clientInstance == nil || !clientInstance.IsConnected() {
		log.Println("[TUN-READER] Android TUN reader: client not connected, exiting")
		return
	}

	log.Println("[TUN-READER] Android TUN reader: client connected, starting read loop")

	for {
		select {
		case <-stopChan:
			log.Println("[TUN-READER] Android TUN reader: stop signal received")
			return
		default:
		}

		if tunDevice == nil {
			log.Println("[TUN-READER] Android TUN reader: tunDevice became nil, exiting")
			return
		}

		data, err := tunDevice.Read()
		if err != nil {
			log.Printf("[TUN-READER] Android TUN read error: %v", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		if len(data) == 0 {
			time.Sleep(10 * time.Millisecond)
			continue
		}
		log.Printf("[TUN-READER] Android TUN read: %d bytes", len(data))
		if clientInstance.IsConnected() {
			if err := clientInstance.Send(data); err != nil {
				log.Printf("[TUN-READER] Android TUN send error: %v", err)
			} else {
				log.Printf("[TUN-READER] Android TUN send: %d bytes sent", len(data))
			}
		}
	}
}

//export StartVPN
func StartVPN(configJSON *C.char) *C.char {
	log.Println("========================================")
	log.Println("[EXPORT] StartVPN: START")
	log.Println("========================================")

	clientMutex.Lock()
	log.Println("[EXPORT] StartVPN: mutex locked")
	defer func() {
		clientMutex.Unlock()
		log.Println("[EXPORT] StartVPN: mutex unlocked")
	}()

	if isRunning {
		log.Println("[EXPORT] StartVPN: already running")
		return C.CString(`{"status":"already_connected"}`)
	}

	if isStopping {
		log.Println("[EXPORT] StartVPN: stopping in progress, wait...")
		clientMutex.Unlock()
		time.Sleep(500 * time.Millisecond)
		clientMutex.Lock()
		if isStopping {
			log.Println("[EXPORT] StartVPN: stop still in progress")
			return C.CString(`{"status":"error","message":"stop in progress"}`)
		}
	}

	configStr := C.GoString(configJSON)
	log.Printf("[EXPORT] StartVPN: config length=%d", len(configStr))
	log.Printf("[EXPORT] StartVPN: config JSON: %s", configStr)

	var flutterConfig FlutterConfig
	if err := json.Unmarshal([]byte(configStr), &flutterConfig); err != nil {
		log.Printf("[EXPORT] StartVPN: json parse error: %v", err)
		return C.CString(`{"status":"error","message":"` + err.Error() + `"}`)
	}

	log.Printf("[EXPORT] StartVPN: parsed - server=%s, mode=%s, protocol=%s, split_tunnel=%v",
		flutterConfig.Server, flutterConfig.Mode, flutterConfig.Protocol, flutterConfig.SplitTunnel)

	if flutterConfig.Server == "" {
		log.Println("[EXPORT] StartVPN: ERROR - server address required")
		return C.CString(`{"status":"error","message":"server address required"}`)
	}

	if flutterConfig.SecretKey == "" {
		log.Println("[EXPORT] StartVPN: ERROR - secret key required")
		return C.CString(`{"status":"error","message":"secret key required"}`)
	}

	if flutterConfig.MTU == 0 {
		flutterConfig.MTU = 1350
		log.Println("[EXPORT] StartVPN: MTU set to default 1350")
	}

	if flutterConfig.Cipher == "" {
		flutterConfig.Cipher = "aes-256-gcm"
		log.Println("[EXPORT] StartVPN: cipher set to default aes-256-gcm")
	}

	if flutterConfig.Mode == "" {
		flutterConfig.Mode = "xray"
		log.Println("[EXPORT] StartVPN: mode set to xray")
	}

	if flutterConfig.Protocol == "" {
		flutterConfig.Protocol = "tcp"
		log.Println("[EXPORT] StartVPN: protocol set to tcp")
	}

	currentServerIP = flutterConfig.Server
	log.Printf("[EXPORT] StartVPN: currentServerIP=%s", currentServerIP)

	if runtime.GOOS == "windows" {
		log.Println("[EXPORT] StartVPN: Windows - setting PATH for wintun.dll")
		exePath, err := os.Executable()
		if err == nil {
			exeDir := filepath.Dir(exePath)
			os.Setenv("PATH", os.Getenv("PATH")+";"+exeDir)
			log.Printf("[EXPORT] StartVPN: Added %s to PATH for wintun.dll", exeDir)
		}
		workDir, err := os.Getwd()
		if err == nil {
			os.Setenv("PATH", os.Getenv("PATH")+";"+workDir)
			log.Printf("[EXPORT] StartVPN: Added %s to PATH for wintun.dll", workDir)
		}
	}

	clientConfig := &engine.ClientConfig{
		TransportConfig: &transport.Config{
			ServerAddr:   flutterConfig.Server,
			Protocol:     flutterConfig.Protocol,
			SecretKey:    flutterConfig.SecretKey,
			MTU:          flutterConfig.MTU,
			Cipher:       flutterConfig.Cipher,
			Mode:         "xray",
			ProxyEnabled: true,
			ProxyType:    "socks5",
			ProxyHost:    "85.120.81.85",
			ProxyPort:    8446,
		},
		SplitTunnel:  flutterConfig.SplitTunnel,
		TUNInterface: "obelisk0",
	}

	log.Printf("[EXPORT] StartVPN: clientConfig created")

	log.Println("[EXPORT] StartVPN: creating client...")
	client := engine.NewClient(clientConfig)
	if client == nil {
		log.Println("[EXPORT] StartVPN: ERROR - failed to create client")
		return C.CString(`{"status":"error","message":"failed to create client"}`)
	}
	log.Printf("[EXPORT] StartVPN: client created, mode=%s", clientConfig.TransportConfig.Mode)

	if runtime.GOOS == "windows" {
		log.Println("[EXPORT] StartVPN: Windows - creating TUN device...")
		tunDev, err := tun.NewTunDevice()
		if err != nil {
			log.Printf("[EXPORT] StartVPN: TUN creation error: %v", err)
			return C.CString(`{"status":"error","message":"` + err.Error() + `"}`)
		}
		tunDevice = tunDev
		log.Println("[EXPORT] StartVPN: TUN device created successfully")

		if err := tunDev.SetupIP("10.0.0.2"); err != nil {
			log.Printf("[EXPORT] StartVPN: TUN IP setup error: %v", err)
			tunDev.Close()
			tunDevice = nil
			cleanupResources()
			return C.CString(`{"status":"error","message":"` + err.Error() + `"}`)
		}
		log.Println("[EXPORT] StartVPN: TUN device created, IP: 10.0.0.2")

		// ========== ИНИЦИАЛИЗАЦИЯ NETSTACK ==========
		if flutterConfig.Mode == "xray" {
			log.Println("[EXPORT] StartVPN: initializing NetStack for Xray")

			netStack := tun.NewNetStack(flutterConfig.MTU, func(data []byte) {
				log.Printf("[NETSTACK] Writing %d bytes to TUN", len(data))
				if tunDevice != nil {
					tunDevice.Write(data)
				}
			})

			// Получаем dialer из outbound
			dialer := func(network, address string) (net.Conn, error) {
				conn := client.GetConn()
				if conn == nil {
					return nil, net.ErrClosed
				}
				// Для Xray режима используем SOCKS5 dialer через outbound
				outbound := client.GetOutbound()
				if outbound != nil && outbound.Dialer() != nil {
					return outbound.Dialer()(network, address)
				}
				return conn, nil
			}

			netStack.Start(dialer)
			netStackInstance = netStack
			log.Println("[EXPORT] StartVPN: NetStack initialized and started")
		}
	}

	// Устанавливаем callback ДО старта
	log.Println("[EXPORT] StartVPN: setting SetOnPacket callback...")
	client.SetOnPacket(func(data []byte) {
		log.Printf("[ON-PACKET] received %d bytes from server", len(data))
		if netStackInstance != nil {
			log.Printf("[ON-PACKET] forwarding to NetStack: %d bytes", len(data))
			netStackInstance.WritePacket(data)
		} else if tunDevice != nil {
			log.Printf("[ON-PACKET] writing %d bytes to TUN", len(data))
			tunDevice.Write(data)
		} else if runtime.GOOS == "android" && onPacketCallback != nil {
			onPacketCallback(data)
		} else {
			log.Printf("[ON-PACKET] no destination, dropping %d bytes", len(data))
		}
	})
	log.Println("[EXPORT] StartVPN: SetOnPacket callback set")

	log.Println("[EXPORT] StartVPN: starting client...")
	if err := client.Start(); err != nil {
		log.Printf("[EXPORT] StartVPN: client start error: %v", err)
		if tunDevice != nil {
			tunDevice.Close()
			tunDevice = nil
		}
		if netStackInstance != nil {
			netStackInstance.Close()
			netStackInstance = nil
		}
		cleanupResources()
		return C.CString(`{"status":"error","message":"` + err.Error() + `"}`)
	}
	log.Println("[EXPORT] StartVPN: client.Start() returned success")

	timeout := time.Now().Add(10 * time.Second)
	log.Println("[EXPORT] StartVPN: waiting for connection...")
	for !client.IsConnected() {
		if time.Now().After(timeout) {
			log.Println("[EXPORT] StartVPN: connection timeout")
			client.Stop()
			if tunDevice != nil {
				tunDevice.Close()
				tunDevice = nil
			}
			if netStackInstance != nil {
				netStackInstance.Close()
				netStackInstance = nil
			}
			cleanupResources()
			return C.CString(`{"status":"error","message":"connection timeout"}`)
		}
		time.Sleep(100 * time.Millisecond)
	}

	log.Println("[EXPORT] StartVPN: client connected to server")

	stopChan = make(chan struct{})
	log.Println("[EXPORT] StartVPN: stopChan created")

	// TUN reader для Windows (читает из TUN и отправляет в client.Send)
	if runtime.GOOS == "windows" && tunDevice != nil {
		log.Println("[EXPORT] StartVPN: Windows - starting TUN reader goroutine")
		tunReaderDone = make(chan struct{})
		go func() {
			defer close(tunReaderDone)
			log.Println("[TUN-READER] Windows TUN reader: STARTED")
			for {
				select {
				case <-stopChan:
					log.Println("[TUN-READER] Windows TUN reader: stop signal received")
					return
				default:
				}
				if tunDevice == nil {
					log.Println("[TUN-READER] Windows TUN reader: tunDevice is nil, exiting")
					return
				}
				data, err := tunDevice.Read()
				if err != nil {
					log.Printf("[TUN-READER] Windows TUN read error: %v", err)
					return
				}
				if len(data) == 0 {
					time.Sleep(10 * time.Millisecond)
					continue
				}
				log.Printf("[TUN-READER] Windows TUN read: %d bytes", len(data))
				if client.IsConnected() {
					if err := client.Send(data); err != nil {
						log.Printf("[TUN-READER] Windows TUN send error: %v", err)
					} else {
						log.Printf("[TUN-READER] Windows TUN send: %d bytes sent", len(data))
					}
				}
			}
		}()
	}

	clientInstance = client
	isRunning = true
	isStopping = false

	log.Println("[EXPORT] StartVPN: SUCCESS - VPN is running")
	log.Println("========================================")
	return C.CString(`{"status":"connected"}`)
}

//export StopVPN
func StopVPN() *C.char {
	log.Println("[EXPORT] StopVPN: START")

	clientMutex.Lock()
	log.Println("[EXPORT] StopVPN: mutex locked")
	defer clientMutex.Unlock()

	if !isRunning {
		log.Println("[EXPORT] StopVPN: already stopped")
		return C.CString(`{"status":"disconnected"}`)
	}

	if isStopping {
		clientMutex.Unlock()
		log.Println("[EXPORT] StopVPN: already stopping")
		return C.CString(`{"status":"disconnected"}`)
	}

	isStopping = true
	log.Println("[EXPORT] StopVPN: stopping VPN...")

	if stopChan != nil {
		log.Println("[EXPORT] StopVPN: closing stopChan")
		close(stopChan)
		stopChan = nil
	}

	cleanupResources()

	log.Println("[EXPORT] StopVPN: VPN stopped successfully")
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
	log.Println("[EXPORT] SetConfig called")
	return C.CString(`{"status":"ok"}`)
}

//export WriteTUN
func WriteTUN(data []byte) {
	log.Printf("[EXPORT] WriteTUN: called with %d bytes", len(data))
	if clientInstance != nil && clientInstance.IsConnected() {
		if err := clientInstance.Send(data); err != nil {
			log.Printf("[EXPORT] WriteTUN: send error: %v", err)
		}
	} else {
		log.Println("[EXPORT] WriteTUN: client not connected")
	}
}

func main() {
	log.SetOutput(os.Stdout)
	log.Println("[MAIN] Go core started")
}