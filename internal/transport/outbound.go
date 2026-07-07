package transport

import (
	"log"
	"net"
	"sync"
	"time"

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
	writeCh    chan []byte
	closeCh    chan struct{}
	wg         sync.WaitGroup
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
		writeCh: make(chan []byte, 5000),
		closeCh: make(chan struct{}),
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

	remoteAddr, err := net.ResolveUDPAddr("udp", o.config.ServerAddr)
	if err != nil {
		return err
	}

	localAddr := &net.UDPAddr{
		IP:   net.IPv4(0, 0, 0, 0),
		Port: 0,
	}

	conn, err := net.DialUDP("udp", localAddr, remoteAddr)
	if err != nil {
		return err
	}

	o.packetConn = conn
	o.remoteAddr = remoteAddr
	o.conn = conn

	log.Printf("[UDP] Connected to %s from %s", o.config.ServerAddr, conn.LocalAddr())
	return nil
}

func (o *Outbound) connectReliableUDP() error {
	log.Printf("[ReliableUDP] Connecting to %s", o.config.ServerAddr)

	windowSize := 1024
	if o.config.WindowSize > 0 {
		windowSize = o.config.WindowSize
	}

	readBuffer := 4194304
	if o.config.ReadBuffer > 0 {
		readBuffer = o.config.ReadBuffer
	}

	writeBuffer := 4194304
	if o.config.WriteBuffer > 0 {
		writeBuffer = o.config.WriteBuffer
	}

	kcpConn, err := kcp.DialWithOptions(o.config.ServerAddr, nil, 10, 3)
	if err != nil {
		return err
	}

	kcpConn.SetStreamMode(false)
	kcpConn.SetWindowSize(windowSize, windowSize)
	kcpConn.SetNoDelay(1, 10, 2, 1)
	kcpConn.SetMtu(o.config.MTU)
	kcpConn.SetReadBuffer(readBuffer)
	kcpConn.SetWriteBuffer(writeBuffer)
	kcpConn.SetACKNoDelay(true)

	o.packetConn = kcpConn
	o.remoteAddr = kcpConn.RemoteAddr()
	o.conn = kcpConn

	o.wg.Add(1)
	go o.writeLoop()

	log.Printf("[ReliableUDP] Connected from %s (window=%d, buffer=%d, mtu=%d)",
		kcpConn.LocalAddr(), windowSize, readBuffer, o.config.MTU)
	return nil
}

func (o *Outbound) keepAliveLoop(conn net.Conn) {
	defer o.wg.Done()
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-o.closeCh:
			return
		case <-ticker.C:
			_, err := conn.Write([]byte{0})
			if err != nil {
				log.Printf("[KeepAlive] Write error: %v", err)
			}
		}
	}
}

func (o *Outbound) writeLoop() {
	defer o.wg.Done()

	for {
		select {
		case <-o.closeCh:
			return
		case data := <-o.writeCh:
			if o.packetConn == nil {
				continue
			}
			_, err := o.packetConn.Write(data)
			if err != nil {
				log.Printf("[Outbound] Write error: %v", err)
			}
		}
	}
}

func (o *Outbound) Write(data []byte) (int, error) {
	if o.conn != nil {
		return o.conn.Write(data)
	}
	if o.packetConn != nil {
		select {
		case o.writeCh <- data:
			return len(data), nil
		default:
			return 0, nil
		}
	}
	return 0, net.ErrClosed
}

func (o *Outbound) Close() error {
	close(o.closeCh)
	o.wg.Wait()

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