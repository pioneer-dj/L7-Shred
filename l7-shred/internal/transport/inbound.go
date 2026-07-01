package transport

import (
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"

	"github.com/l7-shred/core/internal/crypto"
	"github.com/l7-shred/core/internal/proto"
	"github.com/l7-shred/core/internal/shred"
)

type udpPacket struct {
	data []byte
	addr *net.UDPAddr
}

type Inbound struct {
	config     *Config
	listener   net.Listener
	udpConn    *net.UDPConn
	sessionMgr *shred.SessionManager
	cipher     *crypto.AEADCipher
	mixer      *shred.MaskMixer
	arq        *proto.ARQManager
	packetCh   chan udpPacket
	dataCh     chan []byte
	closeCh    chan struct{}
	wg         sync.WaitGroup
	dropCount  uint64
}

func NewInbound(config *Config) (*Inbound, error) {
	secretKeyBytes := []byte(config.SecretKey)
	cipher, err := crypto.NewAEADCipher(secretKeyBytes)
	if err != nil {
		return nil, err
	}

	return &Inbound{
		config:     config,
		sessionMgr: shred.NewSessionManager(),
		cipher:     cipher,
		mixer:      shred.NewMaskMixer(5 * 60 * 1000000000),
		arq:        proto.NewARQManager(),
		packetCh:   make(chan udpPacket, 10000),
		dataCh:     make(chan []byte, 10000),
		closeCh:    make(chan struct{}),
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
	log.Printf("[TCP] Server listening on %s", i.config.ListenAddr)
	go i.acceptLoop()
	return nil
}

func (i *Inbound) startUDP() error {
	addr, err := net.ResolveUDPAddr("udp", i.config.ListenAddr)
	if err != nil {
		return err
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}
	i.udpConn = conn
	log.Printf("[UDP] Server listening on %s (ARQ enabled)", i.config.ListenAddr)

	go i.recvLoop()
	go i.packetLoop()
	return nil
}

func (i *Inbound) recvLoop() {
	buf := make([]byte, 65536)

	for {
		select {
		case <-i.closeCh:
			return
		default:
		}

		n, addr, err := i.udpConn.ReadFromUDP(buf)
		if err != nil {
			continue
		}

		dataCopy := make([]byte, n)
		copy(dataCopy, buf[:n])

		select {
		case i.packetCh <- udpPacket{data: dataCopy, addr: addr}:
		default:
			atomic.AddUint64(&i.dropCount, 1)
		}
	}
}

func (i *Inbound) packetLoop() {
	for {
		select {
		case <-i.closeCh:
			return
		case pkt := <-i.packetCh:
			i.handleUDPPacket(pkt.data, pkt.addr)
		}
	}
}

func (i *Inbound) handleUDPPacket(data []byte, addr *net.UDPAddr) {
	unwrapped, err := i.mixer.Unwrap(data)
	if err != nil {
		return
	}

	frame, err := proto.DecodeFrame(unwrapped)
	if err != nil {
		return
	}

	if frame.Flags == proto.FrameFlagAck {
		if i.arq != nil {
			i.arq.MarkAcked(frame.Ack)
		}
		return
	}

	if frame.Flags == proto.FrameFlagData {
		if i.arq != nil {
			ackFrame := &proto.Frame{
				Flags:  proto.FrameFlagAck,
				Seq:    0,
				Ack:    frame.Seq,
				MaskID: frame.MaskID,
			}
			ackData := ackFrame.Encode()
			ackMasked := i.mixer.Wrap(ackData)
			i.udpConn.WriteToUDP(ackMasked, addr)
		}

		decrypted, err := i.cipher.Decrypt(frame.Payload)
		if err != nil {
			return
		}

		session := i.sessionMgr.CreateSession()
		session.BytesIn += uint64(len(decrypted))

		if len(decrypted) > 0 {
			select {
			case i.dataCh <- decrypted:
			default:
				atomic.AddUint64(&i.dropCount, 1)
			}
		}
	}
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
				log.Printf("[Inbound] Read error: %v", err)
			}
			return
		}

		decrypted, err := i.cipher.Decrypt(buf[:n])
		if err != nil {
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

func (i *Inbound) Accept() (net.Conn, error) {
	if i.listener != nil {
		return i.listener.Accept()
	}
	return nil, net.ErrClosed
}

func (i *Inbound) DataChan() <-chan []byte {
	return i.dataCh
}

func (i *Inbound) Stop() error {
	close(i.closeCh)
	if i.listener != nil {
		i.listener.Close()
	}
	if i.udpConn != nil {
		i.udpConn.Close()
	}
	return nil
}
