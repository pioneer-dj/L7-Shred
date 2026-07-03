package transport

import (
	"net"
	"sync"
	"time"
)

type Dialer struct {
	timeout     time.Duration
	keepAlive   time.Duration
	localAddr   net.Addr
	mu          sync.Mutex
	connections map[string]net.Conn
}

func NewDialer(timeout, keepAlive time.Duration) *Dialer {
	return &Dialer{
		timeout:     timeout,
		keepAlive:   keepAlive,
		connections: make(map[string]net.Conn),
	}
}

func (d *Dialer) Dial(network, address string) (net.Conn, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	key := network + ":" + address
	if conn, exists := d.connections[key]; exists {
		return conn, nil
	}

	conn, err := net.DialTimeout(network, address, d.timeout)
	if err != nil {
		return nil, err
	}

	if tcpConn, ok := conn.(*net.TCPConn); ok {
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(d.keepAlive)
	}

	d.connections[key] = conn
	return conn, nil
}

func (d *Dialer) Close(address string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if conn, exists := d.connections[address]; exists {
		delete(d.connections, address)
		return conn.Close()
	}
	return nil
}

func (d *Dialer) CloseAll() {
	d.mu.Lock()
	defer d.mu.Unlock()

	for _, conn := range d.connections {
		conn.Close()
	}
	d.connections = make(map[string]net.Conn)
}
