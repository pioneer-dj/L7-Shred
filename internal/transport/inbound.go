package transport

import (
	"io"
	"log"
	"net"
	"sync"
	"time"

	"github.com/l7-shred/core/internal/crypto"
	"github.com/l7-shred/core/internal/shred"
	"github.com/xtaci/kcp-go/v5"
)

type Inbound struct {
	config      *Config
	listener    net.Listener
	packetConn  net.PacketConn
	sessionMgr  *shred.SessionManager
	cipher      *crypto.AEADCipher
	udpConns    map[string]*UDPConnWrapper
	udpMu       sync.RWMutex
	kcpListener *kcp.Listener
}

type UDPConnWrapper struct {
	conn       net.PacketConn
	remoteAddr net.Addr
	readChan   chan []byte
	closed     bool
	mu         sync.RWMutex
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
		udpConns:   make(map[string]*UDPConnWrapper),
	}, nil
}

func (i *Inbound) Start() error {
	if i.config.ReliableUDP {
		return i.startReliableUDP()
	}
	if i.config.Mode == "udp" {
		return i.startUDP()
	}
	return i.startTCP()
}

func (i *Inbound) startReliableUDP() error {
	listener, err := kcp.ListenWithOptions(i.config.ListenAddr, nil, 10, 3)
	if err != nil {
		return err
	}
	i.kcpListener = listener
	log.Printf("[KCP] Server listening on %s with KCP", i.config.ListenAddr)
	go i.kcpAcceptLoop()
	return nil
}

func (i *Inbound) kcpAcceptLoop() {
	for {
		kcpConn, err := i.kcpListener.AcceptKCP()
		if err != nil {
			log.Printf("[KCP] Accept error: %v", err)
			return
		}

		kcpConn.SetStreamMode(false)
		kcpConn.SetWindowSize(4096, 4096)
		kcpConn.SetNoDelay(1, 10, 2, 1)
		kcpConn.SetMtu(1400)
		kcpConn.SetReadBuffer(16777216)
		kcpConn.SetWriteBuffer(16777216)
		kcpConn.SetACKNoDelay(true)

		log.Printf("[KCP] New KCP connection from %s", kcpConn.RemoteAddr())
		go i.handleConnection(kcpConn)
	}
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
	packetConn, err := net.ListenPacket("udp", i.config.ListenAddr)
	if err != nil {
		return err
	}
	i.packetConn = packetConn
	log.Printf("[UDP] Server listening on %s (raw UDP)", i.config.ListenAddr)
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
				log.Printf("[Inbound] Read error: %v", err)
			}
			return
		}

		if n == 1 && buf[0] == 0 {
			continue
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
	addrStr := addr.String()

	i.udpMu.RLock()
	wrapper, exists := i.udpConns[addrStr]
	i.udpMu.RUnlock()

	if !exists {
		log.Printf("[UDP] New connection from %s", addrStr)
		wrapper = &UDPConnWrapper{
			conn:       i.packetConn,
			remoteAddr: addr,
			readChan:   make(chan []byte, 5000),
		}
		i.udpMu.Lock()
		i.udpConns[addrStr] = wrapper
		i.udpMu.Unlock()
	}

	select {
	case wrapper.readChan <- data:
	default:
	}
}

func (i *Inbound) Accept() (net.Conn, error) {
	if i.kcpListener != nil {
		return i.kcpListener.AcceptKCP()
	}
	if i.listener != nil {
		return i.listener.Accept()
	}
	if i.packetConn != nil {
		return i.acceptUDP()
	}
	return nil, net.ErrClosed
}

func (i *Inbound) acceptUDP() (net.Conn, error) {
	for {
		i.udpMu.RLock()
		for addrStr, wrapper := range i.udpConns {
			select {
			case data := <-wrapper.readChan:
				i.udpMu.RUnlock()
				return &UDPConn{
					wrapper:    wrapper,
					remoteAddr: wrapper.remoteAddr,
					localAddr:  i.packetConn.LocalAddr(),
					readData:   data,
				}, nil
			default:
			}
			_ = addrStr
		}
		i.udpMu.RUnlock()

		time.Sleep(10 * time.Millisecond)
	}
}

func (i *Inbound) Stop() error {
	if i.kcpListener != nil {
		i.kcpListener.Close()
	}
	if i.listener != nil {
		i.listener.Close()
	}
	if i.packetConn != nil {
		i.packetConn.Close()
	}

	i.udpMu.Lock()
	for _, wrapper := range i.udpConns {
		wrapper.mu.Lock()
		wrapper.closed = true
		close(wrapper.readChan)
		wrapper.mu.Unlock()
	}
	i.udpConns = make(map[string]*UDPConnWrapper)
	i.udpMu.Unlock()

	return nil
}

type UDPConn struct {
	wrapper    *UDPConnWrapper
	remoteAddr net.Addr
	localAddr  net.Addr
	readData   []byte
	closed     bool
	mu         sync.RWMutex
}

func (u *UDPConn) Read(b []byte) (int, error) {
	u.mu.Lock()
	defer u.mu.Unlock()

	if u.closed {
		return 0, net.ErrClosed
	}

	if u.readData != nil {
		n := copy(b, u.readData)
		u.readData = nil
		return n, nil
	}

	select {
	case data, ok := <-u.wrapper.readChan:
		if !ok {
			return 0, net.ErrClosed
		}
		n := copy(b, data)
		if len(data) > n {
			u.readData = data[n:]
		}
		return n, nil
	}
}

func (u *UDPConn) Write(b []byte) (int, error) {
	u.mu.RLock()
	defer u.mu.RUnlock()

	if u.closed {
		return 0, net.ErrClosed
	}

	return u.wrapper.conn.WriteTo(b, u.remoteAddr)
}

func (u *UDPConn) Close() error {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.closed = true
	return nil
}

func (u *UDPConn) LocalAddr() net.Addr {
	return u.localAddr
}

func (u *UDPConn) RemoteAddr() net.Addr {
	return u.remoteAddr
}

func (u *UDPConn) SetDeadline(t time.Time) error {
	return nil
}

func (u *UDPConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (u *UDPConn) SetWriteDeadline(t time.Time) error {
	return nil
}
