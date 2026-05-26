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
		MTU:              1400,
		MultiThreading:   true,
		PaddingEnabled:   true,
		PaddingMin:       32,
		PaddingMax:       288,
		PaddingRotate:    5,
		JitterEnabled:    true,
		JitterMeanMs:     2,
		JitterStdDevMs:   1,
		JitterLossRate:   0.001,
		ChaffingEnabled:  false,
		ChaffingInterval: 1 * time.Second,
		SessionTimeout:   300,
		MaxSessions:      1000,
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
		config.MTU = 1400
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

	return &config, nil
}

func (c *Config) Validate() error {
	if c.ListenAddr == "" && c.ServerAddr == "" {
		return ErrMissingAddress
	}
	if c.MTU < 576 || c.MTU > 9000 {
		return ErrInvalidMTU
	}
	return nil
}

func (c *Config) GetSecretKey() []byte {
	return []byte(c.SecretKey)
}

