package engine

import (
	"crypto/rand"
	"fmt"
	"io"
	"log"
	"net"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/l7-shred/core/internal/shred"
	"github.com/l7-shred/core/internal/transport"
	"github.com/l7-shred/core/internal/tun"
)

type Client struct {
	config       *transport.Config
	outbound     *transport.Outbound
	session      *shred.Session
	sessionMgr   *shred.SessionManager
	handshakeMgr *shred.HandshakeManager
	mixer        *shred.MaskMixer
	stopChan     chan struct{}
	wg           sync.WaitGroup
	authKey      []byte
	connected    bool
	mu           sync.RWMutex
	writeMu      sync.Mutex
	packetsSent  uint64
	packetsRecv  uint64
	bytesSent    uint64
	bytesRecv    uint64
	onPacket     func([]byte)

	handshakeDone    bool
	tunAdded         bool
	currentDomain    string
	background       *BackgroundTraffic
	originalGateway  string
	originalIfIdx    string
	splitTunnel      bool
	defaultGateway   string
	defaultInterface string
	tunInterface     string
	tunIndex         int
	serverIP         string
	serverPort       string
	stopOnce         sync.Once
}

type ClientConfig struct {
	TransportConfig        *transport.Config
	AuthKey                []byte
	Cipher                 string
	SwitchInterval         time.Duration
	Modes                  []shred.ProtocolMode
	HandshakeTimeout       time.Duration
	EnableReplayProtection bool
	DNSServer              string
	DNSOverHTTPS           bool
	TLSSNI                 string
	TLSCertFetch           bool
	FragmentEnabled        bool
	FragmentMin            int
	FragmentMax            int
	BackgroundEnabled      bool
	BackgroundInterval     time.Duration
	ReliableUDP            bool
	SplitTunnel            bool
	TUNInterface           string
}

func DefaultClientConfig(serverAddr string) *ClientConfig {
	authKey := make([]byte, 32)
	rand.Read(authKey)

	return &ClientConfig{
		TransportConfig: &transport.Config{
			ServerAddr: serverAddr,
			Protocol:   "udp",
		},
		AuthKey:        authKey,
		SwitchInterval: 5 * time.Minute,
		Modes: []shred.ProtocolMode{
			shred.ModeVK,
			shred.ModeRuTube,
			shred.ModeYandex,
			shred.ModeOzon,
			shred.ModeWildberries,
			shred.ModeSberID,
			shred.ModeGosuslugi,
			shred.ModeWebRTC,
			shred.ModeQUIC,
			shred.ModeTLS,
		},
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
		SplitTunnel:            true,
		TUNInterface:           "l7shred",
	}
}

func NewClient(config *ClientConfig) *Client {
	if config == nil {
		config = DefaultClientConfig("")
	}

	if config.Cipher == "" {
		config.Cipher = "aes-256-gcm"
	}

	if config.TransportConfig == nil {
		config.TransportConfig = &transport.Config{}
	}
	config.TransportConfig.Cipher = config.Cipher
	config.TransportConfig.SecretKey = string(config.AuthKey)
	config.TransportConfig.DNSServer = config.DNSServer
	config.TransportConfig.DNSOverHTTPS = config.DNSOverHTTPS
	config.TransportConfig.TLSSNI = config.TLSSNI
	config.TransportConfig.TLSCertFetch = config.TLSCertFetch
	config.TransportConfig.FragmentEnabled = config.FragmentEnabled
	config.TransportConfig.FragmentMin = config.FragmentMin
	config.TransportConfig.FragmentMax = config.FragmentMax
	config.TransportConfig.ReliableUDP = config.ReliableUDP
	config.TransportConfig.Protocol = "udp"

	log.Printf("[DEBUG] SplitTunnel: %v", config.SplitTunnel)
	log.Printf("[DEBUG] ReliableUDP: %v", config.ReliableUDP)

	if len(config.AuthKey) == 0 {
		log.Printf("[ERROR] AuthKey is empty! Cannot start client.")
		return nil
	}

	serverHost := strings.Split(config.TransportConfig.ServerAddr, ":")
	serverIP := serverHost[0]
	serverPort := "8443"
	if len(serverHost) > 1 {
		serverPort = serverHost[1]
	}

	sessionMgr := shred.NewSessionManager()
	session := sessionMgr.CreateSessionWithConfig(&shred.SessionConfig{
		SwitchInterval:         config.SwitchInterval,
		Modes:                  config.Modes,
		EnableReplayProtection: config.EnableReplayProtection,
		ReplayWindowSize:       64,
	})

	mixer := shred.NewMaskMixer(config.SwitchInterval)
	mixer.SetModes(config.Modes)

	handshakeMgr := shred.NewHandshakeManager(config.AuthKey, config.HandshakeTimeout)

	client := &Client{
		config:        config.TransportConfig,
		session:       session,
		sessionMgr:    sessionMgr,
		handshakeMgr:  handshakeMgr,
		mixer:         mixer,
		stopChan:      make(chan struct{}),
		authKey:       config.AuthKey,
		handshakeDone: false,
		tunAdded:      false,
		currentDomain: "",
		splitTunnel:   config.SplitTunnel,
		tunInterface:  config.TUNInterface,
		serverIP:      serverIP,
		serverPort:    serverPort,
		stopOnce:      sync.Once{},
	}

	if config.BackgroundEnabled {
		bgConfig := &BackgroundConfig{
			Enabled:   config.BackgroundEnabled,
			Interval:  config.BackgroundInterval,
			JitterMs:  5000,
			Randomize: true,
		}
		client.background = NewBackgroundTraffic(client.Send, bgConfig)
	}

	return client
}

func (c *Client) Start() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.connected {
		return nil
	}

	log.Printf("[Client] Starting client with session ID: %d", c.session.ID)

	if err := c.saveDefaultRoute(); err != nil {
		log.Printf("[Client] Warning: Could not save default route: %v", err)
	}

	outbound, err := transport.NewOutbound(c.config)
	if err != nil {
		log.Printf("[Client] NewOutbound error: %v", err)
		return err
	}

	c.outbound = outbound

	log.Printf("[Client] Outbound created, calling Connect()")
	if err := c.outbound.Connect(); err != nil {
		log.Printf("[Client] Connect error: %v", err)
		return err
	}
	log.Printf("[Client] Connect() successful")

	if conn := c.outbound.Conn(); conn != nil {
		if udpConn, ok := conn.(*net.UDPConn); ok {
			udpConn.SetReadBuffer(4 * 1024 * 1024)
			udpConn.SetWriteBuffer(4 * 1024 * 1024)
			log.Printf("[Client] UDP buffers increased to 4MB")
		}
	}

	if err := c.performHandshake(); err != nil {
		log.Printf("[Client] performHandshake error: %v", err)
		c.outbound.Close()
		return err
	}

	c.wg.Add(1)
	go c.readLoop()

	c.connected = true
	c.handshakeDone = true

	log.Printf("[Client] Connected successfully, using mode: %s", c.mixer.GetCurrentMode().String())

	if err := c.setupRouting(); err != nil {
		log.Printf("[Client] Routing setup warning: %v", err)
	}

	return nil
}

func (c *Client) setupRouting() error {
	log.Printf("[Client] Setting up routing...")

	switch runtime.GOOS {
	case "windows":
		return c.setupWindowsRouting()
	case "linux":
		return c.setupLinuxRouting()
	case "darwin":
		return c.setupDarwinRouting()
	default:
		return fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}
}

func (c *Client) getTUNInterfaceIndex() error {
	cmd := exec.Command("netsh", "interface", "ip", "show", "interfaces")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.Output()
	if err != nil {
		return err
	}

	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		if strings.Contains(line, c.tunInterface) || strings.Contains(line, "l7shred") {
			fields := strings.Fields(line)
			for _, field := range fields {
				if idx, err := strconv.Atoi(field); err == nil && idx > 0 && idx < 1000 {
					c.tunIndex = idx
					log.Printf("[Windows] Found TUN interface with index %d", c.tunIndex)
					return nil
				}
			}
		}
	}
	return fmt.Errorf("TUN interface not found")
}

func (c *Client) setupWindowsRouting() error {
	log.Printf("[Windows] Configuring routes...")

	c.getTUNInterfaceIndex()

	cmd := exec.Command("cmd", "/c", "route delete 0.0.0.0")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	cmd.Run()

	routeCmd := fmt.Sprintf("route add %s mask 255.255.255.255 %s metric 1", c.serverIP, c.defaultGateway)
	cmd = exec.Command("cmd", "/c", routeCmd)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if err := cmd.Run(); err != nil {
		log.Printf("[Windows] Failed to add server route: %v", err)
	}

	var defaultRouteCmd string
	if c.tunIndex > 0 {
		defaultRouteCmd = fmt.Sprintf("route add 0.0.0.0 mask 0.0.0.0 10.0.0.1 metric 1 IF %d", c.tunIndex)
	} else {
		defaultRouteCmd = "route add 0.0.0.0 mask 0.0.0.0 10.0.0.1 metric 1"
	}

	cmd = exec.Command("cmd", "/c", defaultRouteCmd)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if err := cmd.Run(); err != nil {
		log.Printf("[Windows] Failed to add default route: %v", err)
	} else {
		log.Printf("[Windows] Default route added via TUN (metric 1)")
	}

	if c.splitTunnel {
		c.addRussianSubnetRoutes()
	}

	return nil
}

func (c *Client) addRussianSubnetRoutes() {
	log.Printf("[Windows] Adding Russian subnet routes...")

	added := 0
	for _, subnet := range tun.RussianSubnets {
		cmd := exec.Command("cmd", "/c", "route add", subnet, c.defaultGateway, "metric", "1000")
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		if err := cmd.Run(); err == nil {
			added++
		}
	}
	log.Printf("[Windows] Added %d Russian subnet routes", added)
}

func (c *Client) setupLinuxRouting() error {
	log.Printf("[Linux] Configuring routes...")

	exec.Command("ip", "route", "del", "default").Run()
	exec.Command("ip", "route", "add", c.serverIP, "via", c.defaultGateway, "dev", c.defaultInterface).Run()
	exec.Command("ip", "route", "add", "default", "via", "10.0.0.1", "dev", "tun0", "metric", "1").Run()

	if c.splitTunnel {
		added := 0
		for _, subnet := range tun.RussianSubnets {
			if err := exec.Command("ip", "route", "add", subnet, "via", c.defaultGateway, "dev", c.defaultInterface, "metric", "1000").Run(); err == nil {
				added++
			}
		}
		log.Printf("[Linux] Added %d Russian subnet routes", added)
	}

	return nil
}

func (c *Client) setupDarwinRouting() error {
	log.Printf("[Darwin] Configuring routes...")

	exec.Command("route", "delete", "default").Run()
	exec.Command("route", "add", c.serverIP, c.defaultGateway).Run()
	exec.Command("route", "add", "default", "10.0.0.1").Run()

	if c.splitTunnel {
		for _, subnet := range tun.RussianSubnets {
			exec.Command("route", "add", "-net", subnet, c.defaultGateway).Run()
		}
	}

	return nil
}

func (c *Client) saveDefaultRoute() error {
	switch runtime.GOOS {
	case "windows":
		cmd := exec.Command("route", "print", "0.0.0.0")
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		out, err := cmd.Output()
		if err != nil {
			return err
		}
		lines := strings.Split(string(out), "\n")
		for _, line := range lines {
			if strings.Contains(line, "0.0.0.0") && strings.Contains(line, "0.0.0.0") {
				fields := strings.Fields(line)
				if len(fields) >= 3 {
					c.defaultGateway = fields[2]
					log.Printf("[Client] Found default gateway: %s", c.defaultGateway)
					break
				}
			}
		}
	case "linux", "darwin":
		out, err := exec.Command("ip", "route", "show", "default").Output()
		if err != nil {
			return err
		}
		fields := strings.Fields(string(out))
		if len(fields) >= 3 {
			c.defaultGateway = fields[2]
			c.defaultInterface = fields[4]
			log.Printf("[Client] Found default gateway: %s on interface: %s", c.defaultGateway, c.defaultInterface)
		}
	}
	return nil
}

func (c *Client) performHandshake() error {
	log.Printf("[Client] Performing handshake with server...")

	conn := c.getConn()
	if conn == nil {
		log.Printf("[Client] getConn returned nil")
		return net.ErrClosed
	}

	log.Printf("[Client] Got connection, local=%s, remote=%s", conn.LocalAddr(), conn.RemoteAddr())

	err := c.handshakeMgr.PerformClientHandshake(
		conn,
		c.mixer.GetSwitchInterval(),
		c.mixer.GetModes(),
		c.mixer.GetCurrentMode(),
	)

	if err != nil {
		log.Printf("[Client] Handshake failed: %v", err)
		return err
	}

	log.Printf("[Client] Handshake completed successfully")

	c.session.State = shred.SessionStateEstablished
	c.session.SyncModes()

	return nil
}

func (c *Client) getConn() net.Conn {
	if c.outbound == nil {
		return nil
	}
	return c.outbound.Conn()
}

func (c *Client) reconnect() error {
	log.Printf("[Client] Attempting to reconnect...")

	c.mu.Lock()
	c.connected = false
	c.handshakeDone = false
	c.mu.Unlock()

	if c.outbound != nil {
		c.outbound.Close()
		c.outbound = nil
	}

	time.Sleep(1 * time.Second)

	outbound, err := transport.NewOutbound(c.config)
	if err != nil {
		return err
	}
	c.outbound = outbound

	if err := c.outbound.Connect(); err != nil {
		return err
	}

	if conn := c.outbound.Conn(); conn != nil {
		if udpConn, ok := conn.(*net.UDPConn); ok {
			udpConn.SetReadBuffer(4 * 1024 * 1024)
			udpConn.SetWriteBuffer(4 * 1024 * 1024)
		}
	}

	if err := c.performHandshake(); err != nil {
		return err
	}

	c.mu.Lock()
	c.connected = true
	c.handshakeDone = true
	c.mu.Unlock()

	log.Printf("[Client] Reconnected successfully")
	return nil
}

func (c *Client) readLoop() {
	defer c.wg.Done()
	log.Println("[Client] readLoop started")

	buf := make([]byte, 65536)

	for {
		select {
		case <-c.stopChan:
			log.Println("[Client] readLoop: stop signal received, exiting")
			return
		default:
		}

		conn := c.getConn()
		if conn == nil {
			select {
			case <-c.stopChan:
				log.Println("[Client] readLoop: stop signal received (conn nil), exiting")
				return
			case <-time.After(100 * time.Millisecond):
				continue
			}
		}

		readDone := make(chan struct{})
		var n int
		var err error

		go func() {
			n, err = conn.Read(buf)
			close(readDone)
		}()

		select {
		case <-c.stopChan:
			log.Println("[Client] readLoop: stop signal during read, exiting")
			return
		case <-readDone:
			if err != nil {
				if err == io.EOF || strings.Contains(err.Error(), "closed") || strings.Contains(err.Error(), "use of closed") {
					log.Printf("[Client] readLoop: connection closed: %v", err)
					return
				}
				if strings.Contains(err.Error(), "timeout") {
					continue
				}
				log.Printf("[Client] Read error: %v", err)
				time.Sleep(1 * time.Second)
				continue
			}

			if n == 0 {
				continue
			}

			data := make([]byte, n)
			copy(data, buf[:n])

			if !c.handshakeDone {
				continue
			}

			c.mu.Lock()
			c.packetsRecv++
			c.bytesRecv += uint64(n)
			c.mu.Unlock()

			go c.processIncomingPacket(data)
		case <-time.After(500 * time.Millisecond):
			continue
		}
	}
}

func (c *Client) processIncomingPacket(data []byte) {
	unwrapped, err := c.session.Unwrap(data)
	if err != nil {
		log.Printf("[Client] Failed to unwrap packet: %v", err)
		return
	}

	if len(unwrapped) == 0 {
		return
	}

	if len(unwrapped) > 43 && unwrapped[0] == 0x16 {
		sni := extractSNI(unwrapped)
		if sni != "" && sni != c.currentDomain {
			c.currentDomain = sni
			c.mixer.SwitchToDomain(sni)
			log.Printf("[Client] Detected SNI: %s, switched mask", sni)
		}
	}

	if len(unwrapped) >= 20 {
		version := (unwrapped[0] >> 4) & 0x0F
		if version != 4 && version != 6 {
			return
		}
	}

	c.mu.RLock()
	callback := c.onPacket
	c.mu.RUnlock()

	if callback != nil {
		callback(unwrapped)
	}
}

func extractSNI(data []byte) string {
	if len(data) < 43 {
		return ""
	}

	sessionIDLen := int(data[43])
	offset := 44 + sessionIDLen

	if offset+2 > len(data) {
		return ""
	}

	cipherSuitesLen := int(data[offset])<<8 | int(data[offset+1])
	offset += 2 + cipherSuitesLen

	if offset+1 > len(data) {
		return ""
	}

	compressionMethodsLen := int(data[offset])
	offset += 1 + compressionMethodsLen

	if offset+2 > len(data) {
		return ""
	}

	extensionsLen := int(data[offset])<<8 | int(data[offset+1])
	offset += 2
	endExt := offset + extensionsLen

	for offset+4 <= endExt {
		extType := int(data[offset])<<8 | int(data[offset+1])
		extLen := int(data[offset+2])<<8 | int(data[offset+3])
		offset += 4

		if extType == 0x0000 {
			if offset+2 > len(data) {
				return ""
			}
			sniLen := int(data[offset])<<8 | int(data[offset+1])
			offset += 2
			if offset+sniLen <= len(data) {
				return string(data[offset : offset+sniLen])
			}
		}
		offset += extLen
	}

	return ""
}

func (c *Client) Send(payload []byte) error {
	if !c.IsConnected() {
		return net.ErrClosed
	}

	if len(payload) >= 20 {
		version := (payload[0] >> 4) & 0x0F
		if version != 4 && version != 6 {
			return nil
		}
	}

	c.mu.Lock()
	c.packetsSent++
	c.bytesSent += uint64(len(payload))
	c.mu.Unlock()

	wrapped := c.session.Wrap(payload)

	conn := c.getConn()
	if conn == nil {
		return net.ErrClosed
	}

	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	_, err := conn.Write(wrapped)
	return err
}

func (c *Client) SendTo(writer io.Writer, payload []byte) error {
	if !c.IsConnected() {
		return net.ErrClosed
	}

	c.mu.Lock()
	c.packetsSent++
	c.bytesSent += uint64(len(payload))
	c.mu.Unlock()

	wrapped := c.session.Wrap(payload)

	_, err := writer.Write(wrapped)
	return err
}

func (c *Client) IsConnected() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.connected
}

func (c *Client) removeRoutes() {
	log.Printf("[Client] Removing routes...")

	switch runtime.GOOS {
	case "windows":
		cmd := exec.Command("cmd", "/c", "route delete "+c.serverIP)
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		cmd.Run()

		cmd = exec.Command("cmd", "/c", "route delete 0.0.0.0")
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		cmd.Run()

		if c.defaultGateway != "" {
			cmd = exec.Command("cmd", "/c", "route add 0.0.0.0 mask 0.0.0.0 "+c.defaultGateway+" metric 35")
			cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
			cmd.Run()
		}
	case "linux":
		exec.Command("ip", "route", "del", c.serverIP).Run()
		exec.Command("ip", "route", "del", "default", "via", "10.0.0.1").Run()
		if c.defaultGateway != "" && c.defaultInterface != "" {
			exec.Command("ip", "route", "add", "default", "via", c.defaultGateway, "dev", c.defaultInterface).Run()
		}
	case "darwin":
		exec.Command("route", "delete", c.serverIP).Run()
		exec.Command("route", "delete", "default", "10.0.0.1").Run()
		if c.defaultGateway != "" {
			exec.Command("route", "add", "default", c.defaultGateway).Run()
		}
	}
}

func (c *Client) Stop() error {
	log.Println("[Client] Stop() called")

	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.connected {
		log.Println("[Client] Stop() - already stopped")
		return nil
	}

	var stopErr error

	c.stopOnce.Do(func() {
		log.Println("[Client] Stop() - starting...")

		if c.background != nil {
			log.Println("[Client] Stop() - stopping background...")
			c.background.Stop()
			log.Println("[Client] Stop() - background stopped")
		}

		log.Println("[Client] Stop() - closing stopChan...")
		close(c.stopChan)
		log.Println("[Client] Stop() - stopChan closed")

		log.Println("[Client] Stop() - waiting for readLoop...")
		c.wg.Wait()
		log.Println("[Client] Stop() - readLoop finished")

		if c.outbound != nil {
			log.Println("[Client] Stop() - closing outbound...")
			c.outbound.Close()
			log.Println("[Client] Stop() - outbound closed")
		}

		log.Println("[Client] Stop() - removing routes...")
		c.removeRoutes()
		log.Println("[Client] Stop() - routes removed")

		c.connected = false
		c.handshakeDone = false

		log.Printf("[Client] Stop() - stopped. Stats: sent=%d packets (%d bytes), recv=%d packets (%d bytes)",
			c.packetsSent, c.bytesSent, c.packetsRecv, c.bytesRecv)
	})

	return stopErr
}

func (c *Client) ForceRotate() {
	c.mixer.ForceRotate()
	c.session.RotateLocalMask()
	log.Printf("[Client] Forced rotation to mode: %s", c.mixer.GetCurrentMode().String())
}

func (c *Client) GetStats() map[string]interface{} {
	c.mu.RLock()
	defer c.mu.RUnlock()

	stats := make(map[string]interface{})
	stats["connected"] = c.connected
	stats["split_tunnel"] = c.splitTunnel
	stats["session_id"] = c.session.ID
	stats["session_state"] = c.session.State.String()
	stats["packets_sent"] = c.packetsSent
	stats["packets_recv"] = c.packetsRecv
	stats["bytes_sent"] = c.bytesSent
	stats["bytes_recv"] = c.bytesRecv
	stats["current_mode"] = c.mixer.GetCurrentMode().String()
	stats["session_stats"] = c.session.GetStats()

	return stats
}

func (c *Client) GetSession() *shred.Session {
	return c.session
}

func (c *Client) SetOnPacket(callback func([]byte)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.onPacket = callback
}

func (c *Client) SetModes(modes []shred.ProtocolMode) {
	c.mixer.SetModes(modes)
	c.session.MaskConfig.Modes = modes
	c.session.SyncModes()
	log.Printf("[Client] Updated modes: %v", modes)
}

func (c *Client) SetSwitchInterval(interval time.Duration) {
	c.mixer.SetSwitchInterval(interval)
	c.session.MaskConfig.SwitchInterval = interval
	c.session.SyncModes()
}

func (c *Client) GetAuthKey() []byte {
	return c.authKey
}

func (c *Client) SetTunAdded(added bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.tunAdded = added
}

func (c *Client) SetSplitTunnel(enabled bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.splitTunnel = enabled
}