package transport

import (
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/net/websocket"
)

const (
	vlessVersion byte = 0
	vlessCmdTCP  byte = 1
	vlessCmdUDP  byte = 2

	addrTypeIPv4   byte = 1
	addrTypeDomain byte = 2
	addrTypeIPv6   byte = 3
)

type VLESSDialer struct {
	host     string
	port     int
	uuid     uuid.UUID
	path     string
	network  string
	security string
}

func NewVLESSDialer(cfg *Config) (*VLESSDialer, error) {
	host, port := cfg.XrayEndpoint()
	if host == "" {
		return nil, fmt.Errorf("xray endpoint host is required")
	}

	uuidStr := cfg.ProxyUUID
	if uuidStr == "" {
		uuidStr = cfg.SecretKey
	}
	uid, err := uuid.Parse(uuidStr)
	if err != nil {
		return nil, fmt.Errorf("invalid xray uuid: %w", err)
	}

	path := cfg.ProxyPath
	if path == "" {
		path = "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	network := strings.ToLower(cfg.ProxyNetwork)
	if network == "" {
		network = "ws"
	}

	security := strings.ToLower(cfg.ProxySecurity)
	if security == "" {
		security = "none"
	}

	return &VLESSDialer{
		host:     host,
		port:     port,
		uuid:     uid,
		path:     path,
		network:  network,
		security: security,
	}, nil
}

func (d *VLESSDialer) Dial(network, address string) (net.Conn, error) {
	if network != "tcp" && network != "udp" {
		return nil, fmt.Errorf("unsupported network %s", network)
	}

	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	port, err := net.LookupPort(network, portStr)
	if err != nil {
		return nil, err
	}

	cmd := vlessCmdTCP
	if network == "udp" {
		cmd = vlessCmdUDP
	}

	log.Printf("[VLESS] Dial %s/%s via %s:%d", network, address, d.host, d.port)

	switch d.network {
	case "ws", "websocket":
		return d.dialWebSocket(host, uint16(port), cmd)
	default:
		return d.dialTCP(host, uint16(port), cmd)
	}
}

func (d *VLESSDialer) dialWebSocket(targetHost string, targetPort uint16, cmd byte) (net.Conn, error) {
	scheme := "ws"
	if d.security == "tls" || d.security == "reality" {
		scheme = "wss"
	}

	url := fmt.Sprintf("%s://%s:%d%s", scheme, d.host, d.port, d.path)
	origin := fmt.Sprintf("http://%s:%d/", d.host, d.port)

	cfg, err := websocket.NewConfig(url, origin)
	if err != nil {
		return nil, fmt.Errorf("websocket config: %w", err)
	}
	cfg.TlsConfig = nil
	cfg.Header = http.Header{}
	cfg.Header.Set("Host", net.JoinHostPort(d.host, fmt.Sprintf("%d", d.port)))
	cfg.Header.Set("User-Agent", "Mozilla/5.0")

	wsConn, err := websocket.DialConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("websocket dial: %w", err)
	}

	header := buildVLESSHeader(d.uuid, cmd, targetHost, targetPort)
	if err := websocket.Message.Send(wsConn, header); err != nil {
		wsConn.Close()
		return nil, fmt.Errorf("vless header send: %w", err)
	}

	return &wsConnWrapper{Conn: wsConn}, nil
}

func (d *VLESSDialer) dialTCP(targetHost string, targetPort uint16, cmd byte) (net.Conn, error) {
	addr := net.JoinHostPort(d.host, fmt.Sprintf("%d", d.port))
	conn, err := net.DialTimeout("tcp", addr, 15*time.Second)
	if err != nil {
		return nil, err
	}

	header := buildVLESSHeader(d.uuid, cmd, targetHost, targetPort)
	if _, err := conn.Write(header); err != nil {
		conn.Close()
		return nil, fmt.Errorf("vless header send: %w", err)
	}

	return conn, nil
}

func buildVLESSHeader(id uuid.UUID, cmd byte, host string, port uint16) []byte {
	buf := make([]byte, 0, 64)
	buf = append(buf, vlessVersion)
	buf = append(buf, id[:]...)
	buf = append(buf, 0) // addons length
	buf = append(buf, cmd)
	buf = append(buf, byte(port>>8), byte(port))

	ip := net.ParseIP(host)
	switch {
	case ip.To4() != nil:
		buf = append(buf, addrTypeIPv4)
		buf = append(buf, ip.To4()...)
	case ip.To16() != nil && ip.To4() == nil:
		buf = append(buf, addrTypeIPv6)
		buf = append(buf, ip.To16()...)
	default:
		buf = append(buf, addrTypeDomain)
		buf = append(buf, byte(len(host)))
		buf = append(buf, []byte(host)...)
	}
	return buf
}

type wsConnWrapper struct {
	Conn *websocket.Conn
}

func (w *wsConnWrapper) Read(b []byte) (int, error) {
	var msg []byte
	if err := websocket.Message.Receive(w.Conn, &msg); err != nil {
		return 0, err
	}
	return copy(b, msg), nil
}

func (w *wsConnWrapper) Write(b []byte) (int, error) {
	if err := websocket.Message.Send(w.Conn, b); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (w *wsConnWrapper) Close() error {
	return w.Conn.Close()
}

func (w *wsConnWrapper) LocalAddr() net.Addr {
	return w.Conn.LocalAddr()
}

func (w *wsConnWrapper) RemoteAddr() net.Addr {
	return w.Conn.RemoteAddr()
}

func (w *wsConnWrapper) SetDeadline(t time.Time) error {
	return w.Conn.SetDeadline(t)
}

func (w *wsConnWrapper) SetReadDeadline(t time.Time) error {
	return w.Conn.SetReadDeadline(t)
}

func (w *wsConnWrapper) SetWriteDeadline(t time.Time) error {
	return w.Conn.SetWriteDeadline(t)
}

var _ io.Closer = (*wsConnWrapper)(nil)