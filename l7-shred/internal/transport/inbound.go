package transport

import (
	"io"
	"net"

	"github.com/l7-shred/core/internal/crypto"
	"github.com/l7-shred/core/internal/shred"
)

type Inbound struct {
	config     *Config
	listener   net.Listener
	packetConn net.PacketConn
	sessionMgr *shred.SessionManager
	cipher     *crypto.AEADCipher
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
	buf := make([]byte, 65536)

	for {
		n, err := conn.Read(buf)
		if err != nil {
			if err != io.EOF {
				return
			}
			return
		}

		decrypted, err := i.cipher.Decrypt(buf[:n])
		if err != nil {
			conn.Write([]byte("decrypt error"))
			continue
		}

		session.BytesIn += uint64(len(decrypted))

		encrypted, err := i.cipher.Encrypt(decrypted)
		if err != nil {
			conn.Write(decrypted)
			continue
		}

		conn.Write(encrypted)
	}
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
	decrypted, err := i.cipher.Decrypt(data)
	if err != nil {
		return
	}

	encrypted, err := i.cipher.Encrypt(decrypted)
	if err != nil {
		i.packetConn.WriteTo(decrypted, addr)
		return
	}

	i.packetConn.WriteTo(encrypted, addr)
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
