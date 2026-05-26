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

	handshakeChan chan []byte
	handshakeErr  chan error
	handshakeDone bool
	tunAdded      bool
}

type ClientConfig struct {
	TransportConfig        *transport.Config
	AuthKey                []byte
	Cipher                 string
	SwitchInterval         time.Duration
	Modes                  []shred.ProtocolMode
	HandshakeTimeout       time.Duration
	EnableReplayProtection bool
}

func DefaultClientConfig(serverAddr string) *ClientConfig {
	authKey := make([]byte, 32)
	rand.Read(authKey)

	return &ClientConfig{
		TransportConfig: &transport.Config{
			ServerAddr: serverAddr,
			Protocol:   "tcp",
		},
		AuthKey:        authKey,
		SwitchInterval: 5 * time.Minute,
		Modes: []shred.ProtocolMode{
			shred.ModeMinecraft,
			shred.ModeWebRTC,
			shred.ModeQUIC,
			shred.ModeRuTube,
		},
		HandshakeTimeout:       10 * time.Second,
		EnableReplayProtection: true,
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

	log.Printf("[DEBUG] AuthKey length: %d", len(config.AuthKey))
	log.Printf("[DEBUG] Cipher: %s", config.Cipher)

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

	return &Client{
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
	}
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

	c.mu.RLock()
	callback := c.onPacket
	c.mu.RUnlock()

	if callback != nil {
		callback(unwrapped)
	}
}

func (c *Client) Send(payload []byte) error {
	if !c.IsConnected() {
		return net.ErrClosed
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

	if c.tunAdded {
		cmd := exec.Command("route", "delete", "0.0.0.0")
		cmd.Run()
		log.Printf("[Client] Removed default route")
	}

	log.Printf("[Client] Stopping client...")

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
