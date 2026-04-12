package transport

import (
	"io"
	"net"
	"sync"
	"time"

	"github.com/l7-shred/core/internal/crypto"
	"github.com/l7-shred/core/internal/shred"
)

type Outbound struct {
	config     *Config
	conn       net.Conn
	packetConn net.Conn
	session    *shred.Session
	cipher     *crypto.AEADCipher

	mu sync.RWMutex
}

func NewOutbound(config *Config) (*Outbound, error) {
	cipher, err := crypto.NewAEADCipher(config.SecretKey)
	if err != nil {
		return nil, err
	}

	sessionMgr := shred.NewSessionManager()
	session := sessionMgr.CreateSession()

	return &Outbound{
		config:  config,
		session: session,
		cipher:  cipher,
	}, nil
}

func (o *Outbound) Connect() error {
	if o.config.Mode == "udp" {
		return o.connectUDP()
	}
	return o.connectTCP()
}

func (o *Outbound) connectTCP() error {
	conn, err := net.Dial("tcp", o.config.ServerAddr)
	if err != nil {
		return err
	}
	o.conn = conn

	go o.tcpLoop()
	go o.sendTestData()
	return nil
}

func (o *Outbound) connectUDP() error {
	conn, err := net.Dial("udp", o.config.ServerAddr)
	if err != nil {
		return err
	}
	o.packetConn = conn

	go o.udpLoop()
	return nil
}

func (o *Outbound) sendTestData() {
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		testMsg := []byte("ping")
		encrypted, err := o.cipher.Encrypt(testMsg)
		if err != nil {
			continue
		}
		o.conn.Write(encrypted)
	}
}

func (o *Outbound) tcpLoop() {
	buf := make([]byte, 65536)
	for {
		n, err := o.conn.Read(buf)
		if err != nil {
			if err != io.EOF {
				return
			}
			return
		}

		decrypted, err := o.cipher.Decrypt(buf[:n])
		if err != nil {
			continue
		}

		o.session.BytesOut += uint64(len(decrypted))
		println("Client received:", string(decrypted))
	}
}

func (o *Outbound) udpLoop() {
	buf := make([]byte, 65536)
	for {
		n, err := o.packetConn.Read(buf)
		if err != nil {
			return
		}

		encrypted, err := o.cipher.Encrypt(buf[:n])
		if err != nil {
			continue
		}

		o.session.BytesOut += uint64(len(encrypted))
		o.packetConn.Write(encrypted)
	}
}

func (o *Outbound) Close() error {
	if o.conn != nil {
		o.conn.Close()
	}
	if o.packetConn != nil {
		o.packetConn.Close()
	}
	return nil
}

func (o *Outbound) GetConn() net.Conn {
	o.mu.RLock()
	defer o.mu.RUnlock()
	return o.conn
}

func (o *Outbound) Conn() net.Conn {
	return o.conn
}
