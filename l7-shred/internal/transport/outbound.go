package transport

import (
	"net"

	"github.com/l7-shred/core/internal/crypto"
	"github.com/l7-shred/core/internal/engine"
	"github.com/l7-shred/core/internal/shred"
)

type Outbound struct {
	config     *Config
	conn       net.Conn
	packetConn net.PacketConn
	session    *shred.Session
	cipher     *crypto.AEADCipher
	shredder   *engine.Shredder
	serverAddr net.Addr
}

func NewOutbound(config *Config) (*Outbound, error) {
	cipher, err := crypto.NewAEADCipher(config.SecretKey)
	if err != nil {
		return nil, err
	}

	sessionMgr := shred.NewSessionManager()
	session := sessionMgr.CreateSession()

	return &Outbound{
		config:   config,
		session:  session,
		cipher:   cipher,
		shredder: engine.NewShredder(session.ID, cipher),
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

	go o.shredder.Shred(conn, conn)
	return nil
}

func (o *Outbound) connectUDP() error {
	packetConn, err := net.ListenPacket("udp", ":0")
	if err != nil {
		return err
	}

	serverAddr, err := net.ResolveUDPAddr("udp", o.config.ServerAddr)
	if err != nil {
		packetConn.Close()
		return err
	}

	o.packetConn = packetConn
	o.serverAddr = serverAddr

	go o.udpLoop()
	return nil
}

func (o *Outbound) udpLoop() {
	buf := make([]byte, 65536)
	for {
		n, _, err := o.packetConn.ReadFrom(buf)
		if err != nil {
			return
		}

		encrypted, err := o.cipher.Encrypt(buf[:n])
		if err != nil {
			continue
		}

		sessionHeader := make([]byte, 8)
		sessionHeader[0] = byte(o.session.ID >> 56)
		sessionHeader[1] = byte(o.session.ID >> 48)
		sessionHeader[2] = byte(o.session.ID >> 40)
		sessionHeader[3] = byte(o.session.ID >> 32)
		sessionHeader[4] = byte(o.session.ID >> 24)
		sessionHeader[5] = byte(o.session.ID >> 16)
		sessionHeader[6] = byte(o.session.ID >> 8)
		sessionHeader[7] = byte(o.session.ID)

		_, err = o.packetConn.WriteTo(append(sessionHeader, encrypted...), o.serverAddr)
		if err != nil {
			return
		}
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
