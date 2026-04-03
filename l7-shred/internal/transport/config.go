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
	SecretKey        []byte        `json:"secret_key"`
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

	return &config, nil
}
