package tun

import (
	"io"
	"log"
	"net"
	"sync"

	"github.com/eycorsican/go-tun2socks/core"
	"github.com/l7-shred/core/internal/transport"
)

type NetStack struct {
	lwipStack core.LWIPStack
	onPacket  func([]byte)
	dialer    transport.DialFunc
	mu        sync.Mutex
	started   bool
}

func NewNetStack(mtu int, onPacket func([]byte)) *NetStack {
	log.Printf("[NetStack] Creating new netstack with MTU %d", mtu)

	return &NetStack{
		lwipStack: core.NewLWIPStack(),
		onPacket:  onPacket,
	}
}

func (ns *NetStack) Start(dialFn transport.DialFunc) {
	ns.mu.Lock()
	defer ns.mu.Unlock()

	if ns.started {
		return
	}

	ns.dialer = dialFn

	core.RegisterOutputFn(func(data []byte) (int, error) {
		if ns.onPacket != nil {
			ns.onPacket(data)
		}
		return len(data), nil
	})

	core.RegisterTCPConnHandler(&netstackTCPHandler{dialer: dialFn})
	core.RegisterUDPConnHandler(&netstackUDPHandler{dialer: dialFn})

	ns.started = true
	log.Println("[NetStack] handlers registered")
}

func (ns *NetStack) WritePacket(data []byte) {
	if len(data) < 20 {
		return
	}
	ns.lwipStack.Write(data)
}

func (ns *NetStack) Close() {
	ns.lwipStack.Close()
}

type netstackTCPHandler struct {
	dialer transport.DialFunc
}

func (h *netstackTCPHandler) Handle(conn net.Conn, target *net.TCPAddr) error {
	if h.dialer == nil {
		conn.Close()
		return io.ErrClosedPipe
	}

	remote, err := h.dialer("tcp", target.String())
	if err != nil {
		log.Printf("[NetStack] TCP dial error to %s: %v", target, err)
		conn.Close()
		return err
	}

	go pipeConn(conn, remote)
	return nil
}

type netstackUDPHandler struct {
	dialer transport.DialFunc
}

func (h *netstackUDPHandler) Handle(conn core.UDPConn, target *net.UDPAddr) error {
	if h.dialer == nil {
		conn.Close()
		return io.ErrClosedPipe
	}

	remote, err := h.dialer("udp", target.String())
	if err != nil {
		log.Printf("[NetStack] UDP dial error to %s: %v", target, err)
		conn.Close()
		return err
	}

	go pipeUDPConn(conn, remote)
	return nil
}

func pipeConn(local, remote net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		io.Copy(remote, local)
		remote.Close()
	}()

	go func() {
		defer wg.Done()
		io.Copy(local, remote)
		local.Close()
	}()

	wg.Wait()
}

func pipeUDPConn(local core.UDPConn, remote net.Conn) {
	buf := make([]byte, 65535)
	for {
		n, err := remote.Read(buf)
		if err != nil {
			break
		}
		if n > 0 {
			_, _ = local.Write(buf[:n])
		}
	}
	local.Close()
	remote.Close()
}