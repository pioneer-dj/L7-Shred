package transport

import (
	"log"
	"net"
	"sync"

	"github.com/l7-shred/core/internal/crypto"
	"github.com/l7-shred/core/internal/shred"
	"github.com/xtaci/kcp-go/v5"
)

type Outbound struct {
	config     *Config
	conn       net.Conn
	packetConn net.Conn
	remoteAddr net.Addr
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
	if o.config.ReliableUDP {
		return o.connectReliableUDP()
	}
	if o.config.Protocol == "udp" {
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
	log.Printf("[UDP] Connecting to %s", o.config.ServerAddr)

	conn, err := net.Dial("udp", o.config.ServerAddr)
	if err != nil {
		return err
	}
	o.packetConn = conn

	addr, err := net.ResolveUDPAddr("udp", o.config.ServerAddr)
	if err != nil {
		return err
	}
	o.remoteAddr = addr

	log.Printf("[UDP] Connected to %s", o.config.ServerAddr)
	return nil
}

func (o *Outbound) connectReliableUDP() error {
	log.Printf("[ReliableUDP] Connecting to %s", o.config.ServerAddr)

	kcpConn, err := kcp.DialWithOptions(o.config.ServerAddr, nil, 10, 3)
	if err != nil {
		return err
	}

	kcpConn.SetStreamMode(true)
	kcpConn.SetWindowSize(1024, 1024)
	kcpConn.SetNoDelay(1, 20, 2, 1)
	kcpConn.SetMtu(1350)
	kcpConn.SetReadBuffer(4194304)
	kcpConn.SetWriteBuffer(4194304)

	o.packetConn = kcpConn
	o.remoteAddr = kcpConn.RemoteAddr()

	log.Printf("[ReliableUDP] Connected to %s with KCP", o.config.ServerAddr)
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

func (o *Outbound) RemoteAddr() net.Addr {
	return o.remoteAddr
}
