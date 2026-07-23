package transport

import (
	"net"
	"strconv"
	"strings"
)

const (
	ModeL7Shred = "l7-shred"
	ModeXray    = "xray"
)

func (c *Config) EffectiveMode() string {
	switch strings.ToLower(strings.TrimSpace(c.Mode)) {
	case "xray", "vless":
		return ModeXray
	case "l7-shred", "l7shred":
		return ModeL7Shred
	}

	switch strings.ToLower(strings.TrimSpace(c.Protocol)) {
	case "xray", "vless":
		return ModeXray
	case "l7-shred", "l7shred":
		return ModeL7Shred
	}

	return ModeL7Shred
}

func (c *Config) IsXrayMode() bool {
	return c.EffectiveMode() == ModeXray
}

func (c *Config) XrayEndpoint() (host string, port int) {
	host = c.ProxyHost
	port = c.ProxyPort

	if host == "" {
		host, port = splitHostPort(c.ServerAddr, 8446)
	}
	if port == 0 {
		port = 8446
	}
	return host, port
}

func splitHostPort(addr string, defaultPort int) (string, int) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return "", defaultPort
	}
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return addr, defaultPort
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port == 0 {
		return host, defaultPort
	}
	return host, port
}
