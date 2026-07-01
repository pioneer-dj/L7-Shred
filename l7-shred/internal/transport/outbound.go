package transport

import (
	"log"
	"net"
	"sync"
	"sync/atomic"

	"github.com/l7-shred/core/internal/crypto"
	"github.com/l7-shred/core/internal/proto"
	"github.com/l7-shred/core/internal/shred"
)

type Outbound struct {
	config     *Config
	conn       net.Conn
	udpConn    *net.UDPConn
	remoteAddr *net.UDPAddr
	session    *shred.Session
	cipher     *crypto.AEADCipher
	mu         sync.RWMutex
	arq        *proto.ARQManager
	writeCh    chan []byte
	closeCh    chan struct{}
	wg         sync.WaitGroup
	fragmentor *proto.Fragmentor
	mixer      *shred.MaskMixer
	dropCount  uint64
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
		config:     config,
		session:    session,
		cipher:     cipher,
		writeCh:    make(chan []byte, 10000),
		closeCh:    make(chan struct{}),
		fragmentor: proto.NewFragmentor(32, 288),
		mixer:      shred.NewMaskMixer(5 * 60 * 1000000000),
	}, nil
}

func (o *Outbound) Connect() error {
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

	addr, err := net.ResolveUDPAddr("udp", o.config.ServerAddr)
	if err != nil {
		return err
	}

	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return err
	}

	o.udpConn = conn
	o.remoteAddr = addr

	o.arq = proto.NewARQManager()
	o.arq.StartRetransmitLoop(func(data []byte) error {
		_, err := o.udpConn.Write(data)
		return err
	})

	o.wg.Add(1)
	go o.writeLoop()

	log.Printf("[UDP] Connected to %s (ARQ enabled)", o.config.ServerAddr)
	return nil
}

func (o *Outbound) writeLoop() {
	defer o.wg.Done()

	for {
		select {
		case <-o.closeCh:
			return
		case data := <-o.writeCh:
			o.sendWithARQ(data)
		}
	}
}

func (o *Outbound) sendWithARQ(data []byte) {
	encrypted, err := o.cipher.Encrypt(data)
	if err != nil {
		return
	}

	o.fragmentor.FragmentWithCallback(encrypted, func(pb *proto.PoolBuffer) {
		defer pb.Release()

		seq := o.arq.NextSequence()
		maskID := byte(o.mixer.GetCurrentMode())
		frame := &proto.Frame{
			Seq:     seq,
			Ack:     0,
			Flags:   proto.FrameFlagData,
			MaskID:  maskID,
			Payload: pb.Buf[:pb.Len],
		}
		frameData := frame.Encode()

		masked := o.mixer.Wrap(frameData)
		o.arq.StorePacket(seq, masked)

		if _, err := o.udpConn.Write(masked); err != nil {
			return
		}
	})
}

func (o *Outbound) Write(data []byte) (int, error) {
	if o.conn != nil {
		return o.conn.Write(data)
	}
	if o.udpConn != nil {
		select {
		case o.writeCh <- data:
			return len(data), nil
		default:
			atomic.AddUint64(&o.dropCount, 1)
			return 0, nil
		}
	}
	return 0, net.ErrClosed
}

func (o *Outbound) Close() error {
	close(o.closeCh)
	if o.arq != nil {
		o.arq.Stop()
	}
	o.wg.Wait()

	if o.conn != nil {
		o.conn.Close()
	}
	if o.udpConn != nil {
		o.udpConn.Close()
	}
	return nil
}

func (o *Outbound) Conn() net.Conn {
	o.mu.RLock()
	defer o.mu.RUnlock()
	if o.conn != nil {
		return o.conn
	}
	return o.udpConn
}

func (o *Outbound) RemoteAddr() net.Addr {
	return o.remoteAddr
}
