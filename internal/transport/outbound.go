package transport

import (
	"log"
	"net"
	"strconv"
	"sync"

	"golang.org/x/net/proxy"
)

type DialFunc func(network, address string) (net.Conn, error)

type Outbound struct {
	config    *Config
	conn      net.Conn
	proxyConn net.Conn
	mu        sync.RWMutex
	closeCh   chan struct{}
	wg        sync.WaitGroup
	dialer    DialFunc
}

func NewOutbound(config *Config) (*Outbound, error) {
	return &Outbound{
		config:  config,
		closeCh: make(chan struct{}),
	}, nil
}

func (o *Outbound) Connect() error {
	log.Printf("[Outbound] Connect() called, mode=%s, protocol=%s", o.config.Mode, o.config.Protocol)

	if o.config.IsXrayMode() {
		log.Printf("[Xray] Connecting via SOCKS5 to %s", o.config.ServerAddr)

		var proxyAddr string
		if o.config.ProxyEnabled && o.config.ProxyType == "socks5" {
			proxyAddr = net.JoinHostPort(o.config.ProxyHost, strconv.Itoa(o.config.ProxyPort))
			log.Printf("[Xray] Using proxy %s", proxyAddr)
		} else {
			proxyAddr = o.config.ServerAddr
			log.Printf("[Xray] Using direct SOCKS5 at %s", proxyAddr)
		}

		dialer, err := proxy.SOCKS5("tcp", proxyAddr, nil, proxy.Direct)
		if err != nil {
			log.Printf("[Xray] Failed to create SOCKS5 dialer: %v", err)
			return err
		}

		conn, err := dialer.Dial("tcp", o.config.ServerAddr)
		if err != nil {
			log.Printf("[Xray] Failed to dial via SOCKS5: %v", err)
			return err
		}

		o.proxyConn = conn
		o.conn = conn

		o.dialer = func(network, address string) (net.Conn, error) {
			return dialer.Dial(network, address)
		}

		log.Printf("[Xray] Connected to %s via SOCKS5", o.config.ServerAddr)
		return nil
	}

	return nil
}

func (o *Outbound) Write(data []byte) (int, error) {
	if o.conn != nil {
		return o.conn.Write(data)
	}
	return 0, net.ErrClosed
}

func (o *Outbound) Close() error {
	close(o.closeCh)
	o.wg.Wait()

	if o.proxyConn != nil {
		o.proxyConn.Close()
	}
	if o.conn != nil {
		o.conn.Close()
	}
	return nil
}

func (o *Outbound) Conn() net.Conn {
	o.mu.RLock()
	defer o.mu.RUnlock()
	return o.conn
}

func (o *Outbound) RemoteAddr() net.Addr {
	if o.conn != nil {
		return o.conn.RemoteAddr()
	}
	return nil
}

func (o *Outbound) Dialer() DialFunc {
	o.mu.RLock()
	defer o.mu.RUnlock()
	return o.dialer
}