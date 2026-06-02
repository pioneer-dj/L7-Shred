package engine

import (
	"crypto/rand"
	"io"
	"log"
	"net"
	"os/exec"
	"sync"
	"time"

	"github.com/l7-shred/core/internal/shred"
	"github.com/l7-shred/core/internal/transport"
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

	handshakeChan   chan []byte
	handshakeErr    chan error
	handshakeDone   bool
	tunAdded        bool
	currentDomain   string
	background      *BackgroundTraffic
	originalGateway string
	originalIfIdx   string
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

	log.Printf("[DEBUG] AuthKey length: %d", len(config.AuthKey))
	log.Printf("[DEBUG] Cipher: %s", config.Cipher)
	log.Printf("[DEBUG] ReliableUDP: %v", config.ReliableUDP)

	if len(config.AuthKey) == 0 {
		log.Printf("[ERROR] AuthKey is empty! Cannot start client.")
		return nil
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
		handshakeChan: make(chan []byte, 10),
		handshakeErr:  make(chan error, 1),
		handshakeDone: false,
		tunAdded:      false,
		currentDomain: "",
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

	c.wg.Add(1)
	go c.readLoop()

	if err := c.performHandshake(); err != nil {
		log.Printf("[Client] performHandshake error: %v", err)
		c.outbound.Close()
		return err
	}

	c.connected = true
	c.handshakeDone = true

	log.Printf("[Client] Connected successfully, using mode: %s", c.mixer.GetCurrentMode().String())

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

	timeout := 10 * time.Second
	if c.config.SessionTimeout > 0 {
		timeout = time.Duration(c.config.SessionTimeout) * time.Second
	}

	err := c.handshakeMgr.PerformClientHandshakeAsync(
		conn,
		c.mixer.GetSwitchInterval(),
		c.mixer.GetModes(),
		c.handshakeChan,
		c.handshakeErr,
		timeout,
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
		log.Printf("[Client] getConn: outbound is nil")
		return nil
	}
	conn := c.outbound.Conn()
	if conn == nil {
		log.Printf("[Client] getConn: outbound.Conn() returned nil")
	}
	return conn
}

func (c *Client) readLoop() {
	defer c.wg.Done()
	log.Printf("[Client] readLoop started")

	buf := make([]byte, 65536)

	for {
		select {
		case <-c.stopChan:
			log.Printf("[Client] readLoop: stop signal received")
			return
		default:
		}

		conn := c.getConn()
		if conn == nil {
			log.Printf("[Client] readLoop: conn is nil, exiting")
			return
		}

		if !c.handshakeDone {
			n, err := conn.Read(buf)
			if err != nil {
				if c.connected {
					log.Printf("[Client] Read error: %v", err)
				}
				return
			}
			data := make([]byte, n)
			copy(data, buf[:n])

			select {
			case c.handshakeChan <- data:
				log.Printf("[Client] readLoop: sent %d bytes to handshake channel", n)
			default:
				log.Printf("[Client] readLoop: handshake channel full, dropping data")
			}
			continue
		}

		frame, err := readFrame(conn, buf)
		if err != nil {
			if c.connected {
				log.Printf("[Client] Read error: %v", err)
			}
			return
		}

		c.mu.Lock()
		c.packetsRecv++
		c.bytesRecv += uint64(len(frame))
		c.mu.Unlock()

		go c.processIncomingPacket(frame)
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
	return writeFrame(conn, wrapped)
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

func (c *Client) Stop() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.connected {
		return nil
	}

	log.Printf("[Client] Stopping client...")

	if c.background != nil {
		c.background.Stop()
	}

	if c.tunAdded {
		cmd := exec.Command("route", "delete", "0.0.0.0")
		cmd.Run()
		log.Printf("[Client] Removed default route")
	}

	close(c.stopChan)
	c.wg.Wait()

	if c.outbound != nil {
		c.outbound.Close()
	}

	c.connected = false
	c.handshakeDone = false

	log.Printf("[Client] Stopped. Stats: sent=%d packets (%d bytes), recv=%d packets (%d bytes)",
		c.packetsSent, c.bytesSent, c.packetsRecv, c.bytesRecv)

	return nil
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
