package engine

import (
	"io"
	"log"
	"net"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/l7-shred/core/internal/transport"
	"github.com/l7-shred/core/internal/tun"
)

type Client struct {
	config           *transport.Config
	outbound         *transport.Outbound
	stopChan         chan struct{}
	wg               sync.WaitGroup
	connected        bool
	mu               sync.RWMutex
	writeMu          sync.Mutex
	packetsSent      uint64
	packetsRecv      uint64
	bytesSent        uint64
	bytesRecv        uint64
	onPacket         func([]byte)
	defaultGateway   string
	defaultInterface string
	splitTunnel      bool
	tunInterface     string
	tunIndex         int
	serverIP         string
	stopOnce         sync.Once
}

type ClientConfig struct {
	TransportConfig *transport.Config
	SplitTunnel     bool
	TUNInterface    string
}

func NewClient(config *ClientConfig) *Client {
	if config == nil {
		config = &ClientConfig{}
	}

	if config.TransportConfig == nil {
		config.TransportConfig = &transport.Config{}
	}

	serverHost := strings.Split(config.TransportConfig.ServerAddr, ":")
	serverIP := serverHost[0]

	return &Client{
		config:       config.TransportConfig,
		stopChan:     make(chan struct{}),
		splitTunnel:  config.SplitTunnel,
		tunInterface: config.TUNInterface,
		serverIP:     serverIP,
		stopOnce:     sync.Once{},
	}
}

func (c *Client) Start() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.connected {
		return nil
	}

	log.Printf("[Client] Starting client")

	if err := c.saveDefaultRoute(); err != nil {
		log.Printf("[Client] Warning: Could not save default route: %v", err)
	}

	outbound, err := transport.NewOutbound(c.config)
	if err != nil {
		log.Printf("[Client] NewOutbound error: %v", err)
		return err
	}

	c.outbound = outbound

	if err := c.outbound.Connect(); err != nil {
		log.Printf("[Client] Connect error: %v", err)
		return err
	}
	log.Printf("[Client] Connect() successful")

	c.wg.Add(1)
	go c.readLoop()

	c.connected = true
	log.Printf("[Client] Connected successfully, mode: %s", c.config.Mode)

	if err := c.setupRouting(); err != nil {
		log.Printf("[Client] Routing setup warning: %v", err)
	}

	return nil
}

func (c *Client) setupRouting() error {
	log.Printf("[Client] Setting up routing...")

	switch runtime.GOOS {
	case "windows":
		return c.setupWindowsRouting()
	default:
		return nil
	}
}

func (c *Client) setupWindowsRouting() error {
	log.Printf("[Windows] Configuring routes...")

	c.getTUNInterfaceIndex()

	cmd := exec.Command("cmd", "/c", "route delete 0.0.0.0")
	hideWindow(cmd)
	cmd.Run()

	delCmd := exec.Command("cmd", "/c", "route delete "+c.serverIP)
	hideWindow(delCmd)
	delCmd.Run()

	routeCmd := "route add " + c.serverIP + " mask 255.255.255.255 " + c.defaultGateway + " metric 1"
	cmd = exec.Command("cmd", "/c", routeCmd)
	hideWindow(cmd)
	cmd.Run()

	var defaultRouteCmd string
	if c.tunIndex > 0 {
		defaultRouteCmd = "route add 0.0.0.0 mask 0.0.0.0 10.0.0.1 metric 1 IF " + strconv.Itoa(c.tunIndex)
	} else {
		defaultRouteCmd = "route add 0.0.0.0 mask 0.0.0.0 10.0.0.1 metric 1"
	}

	cmd = exec.Command("cmd", "/c", defaultRouteCmd)
	hideWindow(cmd)
	cmd.Run()

	if c.splitTunnel {
		c.addRussianSubnetRoutes()
	}

	return nil
}

func (c *Client) getTUNInterfaceIndex() error {
	cmd := exec.Command("netsh", "interface", "ip", "show", "interfaces")
	hideWindow(cmd)
	out, err := cmd.Output()
	if err != nil {
		return err
	}

	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		if strings.Contains(line, c.tunInterface) || strings.Contains(line, "obelisk") {
			fields := strings.Fields(line)
			for _, field := range fields {
				if idx, err := strconv.Atoi(field); err == nil && idx > 0 && idx < 1000 {
					c.tunIndex = idx
					log.Printf("[Windows] Found TUN interface with index %d", c.tunIndex)
					return nil
				}
			}
		}
	}
	return nil
}

func (c *Client) addRussianSubnetRoutes() {
	log.Printf("[Windows] Adding Russian subnet routes in background...")
	go func() {
		for _, subnet := range tun.RussianSubnets {
			cmd := exec.Command("cmd", "/c", "route add", subnet, c.defaultGateway, "metric", "1000")
			hideWindow(cmd)
			cmd.Run()
		}
	}()
}

func (c *Client) saveDefaultRoute() error {
	switch runtime.GOOS {
	case "windows":
		cmd := exec.Command("route", "print", "0.0.0.0")
		hideWindow(cmd)
		out, err := cmd.Output()
		if err != nil {
			return err
		}
		lines := strings.Split(string(out), "\n")
		for _, line := range lines {
			if strings.Contains(line, "0.0.0.0") {
				fields := strings.Fields(line)
				if len(fields) >= 3 {
					c.defaultGateway = fields[2]
					log.Printf("[Client] Found default gateway: %s", c.defaultGateway)
					break
				}
			}
		}
	}
	return nil
}

func (c *Client) readLoop() {
	defer c.wg.Done()
	log.Println("[Client] readLoop started")

	buf := make([]byte, 65536)

	for {
		select {
		case <-c.stopChan:
			log.Println("[Client] readLoop: stop signal received, exiting")
			return
		default:
		}

		conn := c.getConn()
		if conn == nil {
			time.Sleep(100 * time.Millisecond)
			continue
		}

		readDone := make(chan struct{})
		var n int
		var err error

		go func() {
			n, err = conn.Read(buf)
			close(readDone)
		}()

		select {
		case <-c.stopChan:
			log.Println("[Client] readLoop: stop signal during read, exiting")
			return
		case <-readDone:
			if err != nil {
				if err == io.EOF || strings.Contains(err.Error(), "closed") {
					log.Printf("[Client] readLoop: connection closed: %v", err)
					return
				}
				if strings.Contains(err.Error(), "timeout") {
					continue
				}
				log.Printf("[Client] Read error: %v", err)
				time.Sleep(1 * time.Second)
				continue
			}

			if n == 0 {
				continue
			}

			data := make([]byte, n)
			copy(data, buf[:n])

			log.Printf("[Client] readLoop: received %d bytes from socket", n)

			c.mu.Lock()
			c.packetsRecv++
			c.bytesRecv += uint64(n)
			c.mu.Unlock()

			c.processIncomingPacket(data)
		case <-time.After(500 * time.Millisecond):
			continue
		}
	}
}

func (c *Client) processIncomingPacket(data []byte) {
	log.Printf("[Client] processIncomingPacket: %d bytes, onPacket=%v", len(data), c.onPacket != nil)

	if len(data) == 0 {
		log.Printf("[Client] processIncomingPacket: empty data, skipping")
		return
	}

	c.mu.RLock()
	callback := c.onPacket
	c.mu.RUnlock()

	if callback != nil {
		log.Printf("[Client] processIncomingPacket: calling callback with %d bytes", len(data))
		callback(data)
	} else {
		log.Printf("[Client] processIncomingPacket: No callback, dropping %d bytes", len(data))
	}
}

func (c *Client) Send(payload []byte) error {
	if !c.IsConnected() {
		return net.ErrClosed
	}

	if len(payload) >= 20 {
		version := (payload[0] >> 4) & 0x0F
		if version != 4 && version != 6 {
			return nil
		}
	}

	log.Printf("[Client] Send: %d bytes", len(payload))

	c.mu.Lock()
	c.packetsSent++
	c.bytesSent += uint64(len(payload))
	c.mu.Unlock()

	conn := c.getConn()
	if conn == nil {
		log.Printf("[Client] Send: conn is nil")
		return net.ErrClosed
	}

	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	_, err := conn.Write(payload)
	if err != nil {
		log.Printf("[Client] Send: write error: %v", err)
	}
	return err
}

func (c *Client) IsConnected() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.connected
}

func (c *Client) removeRoutes() {
	log.Printf("[Client] Removing routes...")

	switch runtime.GOOS {
	case "windows":
		cmd := exec.Command("cmd", "/c", "route delete "+c.serverIP)
		hideWindow(cmd)
		cmd.Run()

		cmd = exec.Command("cmd", "/c", "route delete 0.0.0.0")
		hideWindow(cmd)
		cmd.Run()

		if c.defaultGateway != "" {
			cmd = exec.Command("cmd", "/c", "route add 0.0.0.0 mask 0.0.0.0 "+c.defaultGateway+" metric 35")
			hideWindow(cmd)
			cmd.Run()
		}
	}
}

func (c *Client) Stop() error {
	log.Println("[Client] Stop() called")

	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.connected {
		log.Println("[Client] Stop() - already stopped")
		return nil
	}

	c.stopOnce.Do(func() {
		log.Println("[Client] Stop() - starting...")
		close(c.stopChan)
		c.wg.Wait()

		if c.outbound != nil {
			c.outbound.Close()
		}

		c.removeRoutes()
		c.connected = false

		log.Printf("[Client] Stop() - stopped. Stats: sent=%d packets (%d bytes), recv=%d packets (%d bytes)",
			c.packetsSent, c.bytesSent, c.packetsRecv, c.bytesRecv)
	})

	return nil
}

func (c *Client) GetStats() map[string]interface{} {
	c.mu.RLock()
	defer c.mu.RUnlock()

	stats := make(map[string]interface{})
	stats["connected"] = c.connected
	stats["split_tunnel"] = c.splitTunnel
	stats["packets_sent"] = c.packetsSent
	stats["packets_recv"] = c.packetsRecv
	stats["bytes_sent"] = c.bytesSent
	stats["bytes_recv"] = c.bytesRecv

	return stats
}

func (c *Client) SetOnPacket(callback func([]byte)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.onPacket = callback
	log.Println("[Client] SetOnPacket callback set")
}

func (c *Client) getConn() net.Conn {
	if c.outbound == nil {
		return nil
	}
	return c.outbound.Conn()
}

func (c *Client) GetConn() net.Conn {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.outbound == nil {
		return nil
	}
	return c.outbound.Conn()
}

func (c *Client) GetConfig() *transport.Config {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.config
}

func (c *Client) GetOutbound() *transport.Outbound {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.outbound
}

func hideWindow(cmd *exec.Cmd) {
	if runtime.GOOS == "windows" {
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	}
}