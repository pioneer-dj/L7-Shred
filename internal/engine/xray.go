package engine

import (
	"io"
	"log"
	"net"
	"sync"

	"golang.org/x/net/proxy"
)

type XrayTunnel struct {
	socksAddr string
	dialer    proxy.Dialer
	conns     sync.Map
	onPacket  func([]byte)
	stopCh    chan struct{}
}

type XrayStream struct {
	key     string
	conn    net.Conn
	writeCh chan []byte
	done    chan struct{}
	closed  bool
	mu      sync.Mutex
}

func NewXrayTunnel(socksAddr string, onPacket func([]byte)) (*XrayTunnel, error) {
	log.Printf("[Xray] Creating tunnel to %s", socksAddr)

	dialer, err := proxy.SOCKS5("tcp", socksAddr, nil, proxy.Direct)
	if err != nil {
		log.Printf("[Xray] Failed to create SOCKS5 dialer: %v", err)
		return nil, err
	}

	return &XrayTunnel{
		socksAddr: socksAddr,
		dialer:    dialer,
		onPacket:  onPacket,
		stopCh:    make(chan struct{}),
	}, nil
}

func (xt *XrayTunnel) HandlePacket(data []byte) {
	if len(data) < 20 {
		return
	}

	version := (data[0] >> 4) & 0x0F
	if version != 4 {
		return
	}

	ipHdr := data
	srcIP := net.IP(ipHdr[12:16]).String()
	dstIP := net.IP(ipHdr[16:20]).String()
	protocol := ipHdr[9]
	ipHeaderLen := int(ipHdr[0]&0x0F) * 4

	if protocol == 6 && len(data) > ipHeaderLen+20 {
		tcpHdr := data[ipHeaderLen:]
		srcPort := int(tcpHdr[0])<<8 | int(tcpHdr[1])
		dstPort := int(tcpHdr[2])<<8 | int(tcpHdr[3])
		payload := tcpHdr[20:]
		flags := tcpHdr[13]

		key := srcIP + ":" + string(srcPort) + "->" + dstIP + ":" + string(dstPort)

		if flags&0x02 != 0 {
			xt.handleConnect(key, dstIP, dstPort, payload)
		} else if flags&0x01 != 0 {
			xt.handleClose(key)
		} else if len(payload) > 0 {
			xt.handleData(key, payload)
		}
	}
}

func (xt *XrayTunnel) handleConnect(key, dstIP string, dstPort int, initialData []byte) {
	if _, exists := xt.conns.Load(key); exists {
		return
	}

	addr := dstIP + ":" + string(dstPort)
	log.Printf("[Xray] CONNECT to %s", addr)

	conn, err := xt.dialer.Dial("tcp", addr)
	if err != nil {
		log.Printf("[Xray] Dial error for %s: %v", addr, err)
		return
	}

	stream := &XrayStream{
		key:     key,
		conn:    conn,
		writeCh: make(chan []byte, 1000),
		done:    make(chan struct{}),
	}

	xt.conns.Store(key, stream)
	log.Printf("[Xray] Connected to %s", addr)

	if len(initialData) > 0 {
		select {
		case stream.writeCh <- initialData:
		default:
		}
	}

	go xt.handleRead(stream)
	go xt.handleWrite(stream)
}

func (xt *XrayTunnel) handleData(key string, data []byte) {
	val, exists := xt.conns.Load(key)
	if !exists {
		return
	}
	stream := val.(*XrayStream)
	select {
	case stream.writeCh <- data:
	default:
	}
}

func (xt *XrayTunnel) handleClose(key string) {
	val, exists := xt.conns.Load(key)
	if !exists {
		return
	}
	stream := val.(*XrayStream)
	stream.mu.Lock()
	if !stream.closed {
		stream.closed = true
		stream.conn.Close()
		close(stream.done)
	}
	stream.mu.Unlock()
	xt.conns.Delete(key)
}

func (xt *XrayTunnel) handleRead(stream *XrayStream) {
	defer func() {
		stream.conn.Close()
		xt.conns.Delete(stream.key)
	}()

	buf := make([]byte, 65536)
	for {
		select {
		case <-xt.stopCh:
			return
		case <-stream.done:
			return
		default:
		}

		n, err := stream.conn.Read(buf)
		if err != nil {
			if err != io.EOF {
				log.Printf("[Xray] Read error for %s: %v", stream.key, err)
			}
			return
		}
		if n > 0 && xt.onPacket != nil {
			xt.onPacket(buf[:n])
		}
	}
}

func (xt *XrayTunnel) handleWrite(stream *XrayStream) {
	for {
		select {
		case <-xt.stopCh:
			return
		case <-stream.done:
			return
		case data, ok := <-stream.writeCh:
			if !ok {
				return
			}
			stream.mu.Lock()
			if stream.closed {
				stream.mu.Unlock()
				return
			}
			_, err := stream.conn.Write(data)
			stream.mu.Unlock()
			if err != nil {
				return
			}
		}
	}
}

func (xt *XrayTunnel) Close() {
	close(xt.stopCh)
	xt.conns.Range(func(key, value interface{}) bool {
		stream := value.(*XrayStream)
		stream.conn.Close()
		return true
	})
}