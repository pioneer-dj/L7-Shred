package engine

import (
	"sync"
	"time"
)

type ProtocolMode int

const (
	ModeWebRTC ProtocolMode = iota
	ModeQUIC
	ModeTeams
	ModeWinUpdate
	ModeDNSOverHTTPS
)

type ProtocolMixer struct {
	currentMode    ProtocolMode
	modes          []ProtocolMode
	lastSwitch     time.Time
	switchInterval time.Duration
	mu             sync.RWMutex
}

func NewProtocolMixer() *ProtocolMixer {
	return &ProtocolMixer{
		modes:          []ProtocolMode{ModeWebRTC, ModeQUIC, ModeTeams},
		switchInterval: 5 * time.Minute,
	}
}

func (pm *ProtocolMixer) GetCurrentMode() ProtocolMode {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	if time.Since(pm.lastSwitch) > pm.switchInterval {
		pm.mu.RUnlock()
		pm.switchMode()
		pm.mu.RLock()
	}

	return pm.currentMode
}

func (pm *ProtocolMixer) switchMode() {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	currentIndex := -1
	for i, mode := range pm.modes {
		if mode == pm.currentMode {
			currentIndex = i
			break
		}
	}

	nextIndex := (currentIndex + 1) % len(pm.modes)
	pm.currentMode = pm.modes[nextIndex]
	pm.lastSwitch = time.Now()
}

func (pm *ProtocolMixer) GetMaskForMode(mode ProtocolMode) string {
	switch mode {
	case ModeWebRTC:
		return "webrtc/rtp"
	case ModeQUIC:
		return "quic/http3"
	case ModeTeams:
		return "teams/webrtc"
	default:
		return "unknown"
	}
}
