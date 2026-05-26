package transport

import (
	"net"
	"sync"

	"github.com/l7-shred/core/internal/crypto"
	"github.com/l7-shred/core/internal/shred"
)

type Outbound struct {
	config     *Config
	conn       net.Conn
	packetConn net.Conn
	session    *shred.Session
	cipher     *crypto.AEADCipher
	mu         sync.RWMutex
}

func NewOutbound(config *Config) (*Outbound, error) {
	secretKeyBytes := []byte(config.SecretKey)
	cipher, err := crypto.NewAEADCipher(secretKeyBytes)
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
	return nil
}

func (o *Outbound) connectUDP() error {
	conn, err := net.Dial("udp", o.config.ServerAddr)
	if err != nil {
		return err
	}
	o.packetConn = conn
	return nil
}

func (o *Outbound) Write(data []byte) (int, error) {
	if o.conn != nil {
		return o.conn.Write(data)
	}
	if o.packetConn != nil {
		return o.packetConn.Write(data)
	}
	return 0, net.ErrClosed
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

func (o *Outbound) Conn() net.Conn {
	o.mu.RLock()
	defer o.mu.RUnlock()
	if o.conn != nil {
		return o.conn
	}
	return o.packetConn
}

