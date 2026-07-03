package transport

import (
	"encoding/json"
	"os"
	"time"
)

type Config struct {
	ServerAddr       string        `json:"server"`
	ListenAddr       string        `json:"listen"`
	Mode             string        `json:"mode"`
	Protocol         string        `json:"protocol"`
	SecretKey        string        `json:"secret_key"`
	Cipher           string        `json:"cipher"`
	PostQuantum      bool          `json:"post_quantum"`
	MTU              int           `json:"mtu"`
	MultiThreading   bool          `json:"multi_threading"`
	PaddingEnabled   bool          `json:"padding_enabled"`
	PaddingMin       int           `json:"padding_min"`
	PaddingMax       int           `json:"padding_max"`
	PaddingRotate    int           `json:"padding_rotate_interval"`
	JitterEnabled    bool          `json:"jitter_enabled"`
	JitterMeanMs     int           `json:"jitter_mean_ms"`
	JitterStdDevMs   int           `json:"jitter_stddev_ms"`
	JitterLossRate   float64       `json:"jitter_loss_rate"`
	ChaffingEnabled  bool          `json:"chaffing_enabled"`
	ChaffingInterval time.Duration `json:"chaffing_interval"`
	ChaffTargets     []string      `json:"chaffing_targets"`
	SessionTimeout   int           `json:"session_timeout"`
	MaxSessions      int           `json:"max_sessions"`
	FragmentEnabled  bool          `json:"fragment_enabled"`
	FragmentMin      int           `json:"fragment_min"`
	FragmentMax      int           `json:"fragment_max"`
	DNSServer        string        `json:"dns_server"`
	DNSOverHTTPS     bool          `json:"dns_over_https"`
	TLSSNI           string        `json:"tls_sni"`
	TLSCertFetch     bool          `json:"tls_cert_fetch"`
	ReliableUDP      bool          `json:"reliable_udp"`
	SplitTunnel      bool          `json:"split_tunnel"`
	CongestionCtrl   bool          `json:"congestion_control"`
	MaxCwnd          int           `json:"max_cwnd"`
	Modes          []string `json:"modes"`
    SwitchInterval int      `json:"switch_interval"`
	WindowSize  int `json:"window_size"`
    ReadBuffer  int `json:"read_buffer"`
    WriteBuffer int `json:"write_buffer"`

	OnPacket func([]byte) `json:"-"`
}

func DefaultConfig() *Config {
	return &Config{
		ServerAddr:       "",
		ListenAddr:       ":8443",
		Mode:             "udp",
		Protocol:         "udp",
		Cipher:           "aes-256-gcm",
		PostQuantum:      false,
		MTU:              1350,
		MultiThreading:   true,
		PaddingEnabled:   true,
		PaddingMin:       16,
		PaddingMax:       64,
		PaddingRotate:    5,
		JitterEnabled:    true,
		JitterMeanMs:     5,
		JitterStdDevMs:   3,
		JitterLossRate:   0.001,
		ChaffingEnabled:  false,
		ChaffingInterval: 1 * time.Second,
		SessionTimeout:   300,
		MaxSessions:      1000,
		FragmentEnabled:  true,
		FragmentMin:      32,
		FragmentMax:      288,
		DNSServer:        "8.8.8.8",
		DNSOverHTTPS:     true,
		TLSSNI:           "www.google.com",
		TLSCertFetch:     true,
		ReliableUDP:      true,
		SplitTunnel:      true,
		CongestionCtrl:   true,
		MaxCwnd:          65535,
	}
}

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, err
	}

	if config.MTU == 0 {
		config.MTU = 1350
	}
	if config.Cipher == "" {
		config.Cipher = "aes-256-gcm"
	}
	if config.SessionTimeout == 0 {
		config.SessionTimeout = 300
	}
	if config.MaxSessions == 0 {
		config.MaxSessions = 1000
	}
	if config.FragmentMin == 0 {
		config.FragmentMin = 32
	}
	if config.FragmentMax == 0 {
		config.FragmentMax = 288
	}
	if config.PaddingMin == 0 {
		config.PaddingMin = 16
	}
	if config.PaddingMax == 0 {
		config.PaddingMax = 64
	}
	if config.JitterMeanMs == 0 {
		config.JitterMeanMs = 5
	}
	if config.DNSServer == "" {
		config.DNSServer = "8.8.8.8"
	}
	if config.TLSSNI == "" {
		config.TLSSNI = "www.google.com"
	}
	if config.MaxCwnd == 0 {
		config.MaxCwnd = 65535
	}

	return &config, nil
}

func (c *Config) Validate() error {
	if c.ListenAddr == "" && c.ServerAddr == "" {
		return ErrMissingAddress
	}
	if c.MTU < 576 || c.MTU > 9000 {
		return ErrInvalidMTU
	}
	if c.FragmentMin < 32 || c.FragmentMin > 1500 {
		return ErrInvalidFragmentMin
	}
	if c.FragmentMax < c.FragmentMin || c.FragmentMax > 1500 {
		return ErrInvalidFragmentMax
	}
	if c.ReliableUDP && c.Protocol == "tcp" {
		c.Protocol = "udp"
	}
	return nil
}

func (c *Config) GetSecretKey() []byte {
	return []byte(c.SecretKey)
}
