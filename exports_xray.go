package main

import "C"
import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"log"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/tun"
)

var (
	xrayConn      net.Conn
	xrayMutex     sync.Mutex
	xrayRunning   bool
	xrayStopChan  chan struct{}
	uuidBytes     []byte
	tunDevice     tun.Device
	tunName       string
	serverAddress string
)

func parseUUID(uuidStr string) []byte {
	s := strings.ReplaceAll(uuidStr, "-", "")
	if len(s) != 32 {
		return nil
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil
	}
	return b
}

func buildVLESSRequest(uuid []byte, dstIP string, dstPort int) []byte {
	packet := make([]byte, 0, 1+16+1+1+2+1+4)
	packet = append(packet, 0)
	packet = append(packet, uuid...)
	packet = append(packet, 0)
	packet = append(packet, 1)

	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(dstPort))
	packet = append(packet, portBytes...)

	packet = append(packet, 1)
	ip := net.ParseIP(dstIP)
	if ip != nil {
		ipv4 := ip.To4()
		if ipv4 != nil {
			packet = append(packet, ipv4...)
		}
	}
	return packet
}

func getTUNInterfaceIndex(name string) int {
	out, err := exec.Command("netsh", "interface", "ip", "show", "interfaces").Output()
	if err != nil {
		return 0
	}
	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		if strings.Contains(line, name) {
			fields := strings.Fields(line)
			for _, field := range fields {
				if idx, err := strconv.Atoi(field); err == nil && idx > 0 && idx < 1000 {
					return idx
				}
			}
		}
	}
	return 0
}

func proxyToXray(dstIP string, dstPort int, payload []byte) {
	log.Printf("[TCP] Opening connection to %s:%d", dstIP, dstPort)

	conn, err := net.DialTimeout("tcp", serverAddress, 10*time.Second)
	if err != nil {
		log.Printf("[TCP] Xray dial error: %v", err)
		return
	}
	defer conn.Close()

	vlessHeader := buildVLESSRequest(uuidBytes, dstIP, dstPort)
	conn.Write(vlessHeader)
	conn.Write(payload)

	log.Printf("[TCP] Sent to %s:%d (header=%d, payload=%d)", dstIP, dstPort, len(vlessHeader), len(payload))

	buf := make([]byte, 65536)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			if err.Error() != "EOF" {
				log.Printf("[TCP] Read error from Xray: %v", err)
			}
			return
		}
		if n > 0 && tunDevice != nil {
			// Логируем запись в TUN
			log.Printf("[TCP] Writing %d bytes to TUN", n)
			// Выводим первые 20 байт для отладки
			if n > 20 {
				log.Printf("[TCP] First 20 bytes: %x", buf[:20])
			} else {
				log.Printf("[TCP] First %d bytes: %x", n, buf[:n])
			}
			tunDevice.Write([][]byte{buf[:n]}, 0)
		}
	}
}

func handlePacket(data []byte) {
	if len(data) < 20 {
		return
	}

	version := (data[0] >> 4) & 0xF
	if version != 4 {
		return
	}

	headerLen := int(data[0]&0x0F) * 4
	if len(data) < headerLen+4 {
		return
	}

	protocol := data[9]
	if protocol != 6 {
		return
	}

	dstIP := net.IP(data[16:20]).String()
	dstPort := int(binary.BigEndian.Uint16(data[headerLen+2 : headerLen+4]))

	if dstIP == "" || dstPort == 0 {
		return
	}

	tcpHeaderLen := int((data[headerLen+12] >> 4) * 4)
	payloadStart := headerLen + tcpHeaderLen
	if payloadStart >= len(data) {
		return
	}
	payload := data[payloadStart:]

	if len(payload) == 0 {
		return
	}

	go proxyToXray(dstIP, dstPort, payload)
}

// ==================== EXPORTS ====================

//export XrayConnect
func XrayConnect(serverAddr *C.char, uuid *C.char) *C.char {
	addr := C.GoString(serverAddr)
	uid := C.GoString(uuid)

	log.Printf("[XRAY] Connecting to %s", addr)

	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		log.Printf("[XRAY] Connection error: %v", err)
		return C.CString(`{"status":"error","message":"` + err.Error() + `"}`)
	}
	conn.Close()

	uuidBytes = parseUUID(uid)
	if uuidBytes == nil || len(uuidBytes) != 16 {
		return C.CString(`{"status":"error","message":"invalid UUID"}`)
	}

	serverAddress = addr

	xrayMutex.Lock()
	xrayRunning = true
	xrayStopChan = make(chan struct{})
	xrayMutex.Unlock()

	log.Printf("[XRAY] Ready")
	return C.CString(`{"status":"connected"}`)
}

//export XrayStartTUN
func XrayStartTUN(mtu C.int) *C.char {
	log.Printf("[XRAY] Starting TUN")

	exec.Command("wintun", "delete", "xraytun").Run()

	dev, err := tun.CreateTUN("xraytun", int(mtu))
	if err != nil {
		log.Printf("[XRAY] TUN error: %v", err)
		return C.CString(`{"status":"error","message":"` + err.Error() + `"}`)
	}
	tunDevice = dev
	tunName, _ = dev.Name()

	log.Printf("[XRAY] TUN device created: %s", tunName)

	exec.Command("netsh", "interface", "ip", "set", "address",
		"name="+tunName, "source=static", "addr=10.0.0.2", "mask=255.255.255.0").Run()

	log.Printf("[XRAY] TUN: %s IP 10.0.0.2", tunName)

	ifIdx := getTUNInterfaceIndex(tunName)
	if ifIdx > 0 {
		log.Printf("[XRAY] TUN interface index: %d", ifIdx)

		exec.Command("route", "delete", "0.0.0.0").Run()
		exec.Command("route", "add", "85.120.81.85", "mask", "255.255.255.255", "172.20.10.1", "metric", "1").Run()
		exec.Command("route", "add", "0.0.0.0", "mask", "0.0.0.0", "10.0.0.1", "metric", "1", "if", strconv.Itoa(ifIdx)).Run()
		log.Printf("[XRAY] Routes configured")
	} else {
		log.Printf("[XRAY] WARNING: Could not find TUN interface index")
	}

	go tunReadLoop()
	return C.CString(`{"status":"tun_started"}`)
}

func tunReadLoop() {
	log.Println("[TUN] Reader started")
	buf := make([]byte, 1500)
	bufs := make([][]byte, 1)
	bufs[0] = buf
	sizes := make([]int, 1)

	for {
		select {
		case <-xrayStopChan:
			log.Println("[TUN] Stopped")
			return
		default:
		}
		if tunDevice == nil {
			time.Sleep(100 * time.Millisecond)
			continue
		}
		n, err := tunDevice.Read(bufs, sizes, 0)
		if err != nil {
			time.Sleep(100 * time.Millisecond)
			continue
		}
		if n > 0 && sizes[0] > 0 {
			log.Printf("[TUN] Read %d bytes from TUN", sizes[0])
			handlePacket(bufs[0][:sizes[0]])
		}
	}
}

//export XrayStop
func XrayStop() *C.char {
	log.Println("[XRAY] Stopping")
	xrayMutex.Lock()
	defer xrayMutex.Unlock()

	if xrayStopChan != nil {
		close(xrayStopChan)
		xrayStopChan = nil
	}

	if tunDevice != nil {
		tunDevice.Close()
		tunDevice = nil
	}

	exec.Command("route", "delete", "0.0.0.0").Run()
	exec.Command("wintun", "delete", "xraytun").Run()

	xrayRunning = false
	return C.CString(`{"status":"stopped"}`)
}

//export XrayDisconnect
func XrayDisconnect() *C.char { return XrayStop() }

//export XrayStatus
func XrayStatus() *C.char {
	status := map[string]interface{}{"connected": xrayRunning}
	jsonData, _ := json.Marshal(status)
	return C.CString(string(jsonData))
}

func main() {
	log.SetOutput(os.Stdout)
	log.Println("[XRAY] Core initialized")
}