package transport

import (
	"net"

	"github.com/l7-shred/core/internal/crypto"
	"github.com/l7-shred/core/internal/engine"
	"github.com/l7-shred/core/internal/shred"
)

type Inbound struct {
	config     *Config
	listener   net.Listener
	packetConn net.PacketConn
	sessionMgr *shred.SessionManager
	cipher     *crypto.AEADCipher
	mixer      *engine.ProtocolMixer
}

func NewInbound(config *Config) (*Inbound, error) {
	cipher, err := crypto.NewAEADCipher(config.SecretKey)
	if err != nil {
		return nil, err
	}

	return &Inbound{
		config:     config,
		sessionMgr: shred.NewSessionManager(),
		cipher:     cipher,
		mixer:      engine.NewProtocolMixer(),
	}, nil
}

func (i *Inbound) Start() error {
	if i.config.Mode == "udp" {
		return i.startUDP()
	}
	return i.startTCP()
}

func (i *Inbound) startTCP() error {
	listener, err := net.Listen("tcp", i.config.ListenAddr)
	if err != nil {
		return err
	}
	i.listener = listener

	go i.acceptLoop()
	return nil
}

func (i *Inbound) startUDP() error {
	packetConn, err := net.ListenPacket("udp", i.config.ListenAddr)
	if err != nil {
		return err
	}
	i.packetConn = packetConn

	go i.packetLoop()
	return nil
}

func (i *Inbound) acceptLoop() {
	for {
		conn, err := i.listener.Accept()
		if err != nil {
			return
		}
		go i.handleConnection(conn)
	}
}

func (i *Inbound) handleConnection(conn net.Conn) {
	defer conn.Close()

	session := i.sessionMgr.CreateSession()
	shredder := engine.NewShredder(session.ID, i.cipher)

	shredder.Shred(conn, conn)
}

func (i *Inbound) packetLoop() {
	buf := make([]byte, 65536)
	for {
		n, addr, err := i.packetConn.ReadFrom(buf)
		if err != nil {
			return
		}
		go i.handlePacket(buf[:n], addr)
	}
}

func (i *Inbound) handlePacket(data []byte, addr net.Addr) {
	sessionID := uint64(data[0])<<56 | uint64(data[1])<<48 | uint64(data[2])<<40 | uint64(data[3])<<32
	session := i.sessionMgr.GetSession(sessionID)
	if session == nil {
		return
	}

	decrypted, err := i.cipher.Decrypt(data[8:])
	if err != nil {
		return
	}

	i.packetConn.WriteTo(decrypted, addr)
}

func (i *Inbound) Stop() error {
	if i.listener != nil {
		i.listener.Close()
	}
	if i.packetConn != nil {
		i.packetConn.Close()
	}
	return nil
}
