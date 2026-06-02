package engine

import (
	"sync"
	"time"

	"github.com/l7-shred/core/internal/masks"
)

type ProtocolMode int

const (
	ModeWebRTC ProtocolMode = iota
	ModeQUIC
	ModeTeams
	ModeWinUpdate
	ModeDNSOverHTTPS
	ModeRuTube
	ModeYandex
	ModeVK
	ModeSTUN
	ModeZoom
	ModeMinecraft
	ModeTLS
)

func (m ProtocolMode) String() string {
	switch m {
	case ModeWebRTC:
		return "webrtc"
	case ModeQUIC:
		return "quic"
	case ModeTeams:
		return "teams"
	case ModeWinUpdate:
		return "winupdate"
	case ModeDNSOverHTTPS:
		return "doh"
	case ModeRuTube:
		return "rutube"
	case ModeYandex:
		return "yandex"
	case ModeVK:
		return "vk"
	case ModeSTUN:
		return "stun"
	case ModeZoom:
		return "zoom"
	case ModeMinecraft:
		return "minecraft"
	default:
		return "unknown"
	}
}

type MaskFactory struct {
	mu sync.RWMutex
}

func NewMaskFactory() *MaskFactory {
	return &MaskFactory{}
}

func (f *MaskFactory) CreateMask(mode ProtocolMode) masks.Masker {
	switch mode {
	case ModeWebRTC:
		return masks.NewWebRTCMask()
	case ModeQUIC:
		return masks.NewQUICMask()
	case ModeTeams:
		return masks.NewTeamsMask()
	case ModeWinUpdate:
		return masks.NewWinUpdateMask()
	case ModeDNSOverHTTPS:
		return masks.NewDNSOverHTTPSMask()
	case ModeRuTube:
		return masks.NewRuTubeMask()
	case ModeYandex:
		return masks.NewYandexMask()
	case ModeVK:
		return masks.NewVKMask()
	case ModeSTUN:
		return masks.NewSTUNMask()
	case ModeZoom:
		return masks.NewZoomMask()
	case ModeTLS:
		return masks.NewTLSMask()
	default:
		return masks.NewVKMask()
	}
}

type ProtocolMixer struct {
	currentMode    ProtocolMode
	currentMask    masks.Masker
	modes          []ProtocolMode
	lastSwitch     time.Time
	switchInterval time.Duration
	factory        *MaskFactory
	mu             sync.RWMutex

	stats            map[ProtocolMode]int64
	packetsWrapped   int64
	packetsUnwrapped int64
	errorsCount      int64
}

func NewProtocolMixer() *ProtocolMixer {
	mixer := &ProtocolMixer{
		modes:          []ProtocolMode{ModeRuTube, ModeYandex, ModeVK, ModeQUIC, ModeWebRTC, ModeMinecraft},
		switchInterval: 5 * time.Minute,
		lastSwitch:     time.Now(),
		currentMode:    ModeRuTube,
		factory:        NewMaskFactory(),
		stats:          make(map[ProtocolMode]int64),
	}

	mixer.currentMask = mixer.factory.CreateMask(mixer.currentMode)

	return mixer
}

func (pm *ProtocolMixer) GetCurrentMode() ProtocolMode {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	if pm.switchInterval > 0 && time.Since(pm.lastSwitch) > pm.switchInterval {
		pm.mu.RUnlock()
		pm.switchMode()
		pm.mu.RLock()
	}

	return pm.currentMode
}

func (pm *ProtocolMixer) GetCurrentMask() masks.Masker {
	pm.GetCurrentMode()
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return pm.currentMask
}

func (pm *ProtocolMixer) Wrap(payload []byte) []byte {
	mask := pm.GetCurrentMask()

	pm.mu.Lock()
	pm.packetsWrapped++
	pm.stats[pm.currentMode]++
	pm.mu.Unlock()

	return mask.Wrap(payload)
}

func (pm *ProtocolMixer) Unwrap(data []byte) ([]byte, error) {
	mask := pm.GetCurrentMask()
	result, err := mask.Unwrap(data)
	if err == nil {
		pm.mu.Lock()
		pm.packetsUnwrapped++
		pm.mu.Unlock()
		return result, nil
	}

	pm.mu.RLock()
	modes := make([]ProtocolMode, len(pm.modes))
	copy(modes, pm.modes)
	pm.mu.RUnlock()

	for _, mode := range modes {
		testMask := pm.factory.CreateMask(mode)
		result, err := testMask.Unwrap(data)
		if err == nil {
			pm.mu.Lock()
			pm.currentMode = mode
			pm.currentMask = testMask
			pm.packetsUnwrapped++
			pm.mu.Unlock()
			return result, nil
		}
	}

	pm.mu.Lock()
	pm.errorsCount++
	pm.mu.Unlock()

	return nil, masks.ErrUnwrapFailed
}

func (pm *ProtocolMixer) switchMode() {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if len(pm.modes) == 0 {
		return
	}

	currentIndex := -1
	for i, mode := range pm.modes {
		if mode == pm.currentMode {
			currentIndex = i
			break
		}
	}

	nextIndex := (currentIndex + 1) % len(pm.modes)
	newMode := pm.modes[nextIndex]

	newMask := pm.factory.CreateMask(newMode)

	pm.currentMode = newMode
	pm.currentMask = newMask
	pm.lastSwitch = time.Now()
}

func (pm *ProtocolMixer) SetModes(modes []ProtocolMode) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if len(modes) == 0 {
		return
	}

	pm.modes = modes
	pm.currentMode = modes[0]
	pm.currentMask = pm.factory.CreateMask(pm.currentMode)
	pm.lastSwitch = time.Now()
}

func (pm *ProtocolMixer) SetSwitchInterval(interval time.Duration) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	pm.switchInterval = interval
}

func (pm *ProtocolMixer) GetMaskForMode(mode ProtocolMode) string {
	return mode.String()
}

func (pm *ProtocolMixer) GetStats() map[string]interface{} {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	stats := make(map[string]interface{})
	stats["current_mode"] = pm.currentMode.String()
	stats["packets_wrapped"] = pm.packetsWrapped
	stats["packets_unwrapped"] = pm.packetsUnwrapped
	stats["errors"] = pm.errorsCount
	stats["modes_count"] = len(pm.modes)

	modeStats := make(map[string]int64)
	for mode, count := range pm.stats {
		modeStats[mode.String()] = count
	}
	stats["mode_stats"] = modeStats

	return stats
}

func (pm *ProtocolMixer) ResetStats() {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	pm.packetsWrapped = 0
	pm.packetsUnwrapped = 0
	pm.errorsCount = 0
	pm.stats = make(map[ProtocolMode]int64)
}

func (pm *ProtocolMixer) ForceSwitch() {
	pm.switchMode()
}

func (pm *ProtocolMixer) AddMode(mode ProtocolMode) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	for _, m := range pm.modes {
		if m == mode {
			return
		}
	}

	pm.modes = append(pm.modes, mode)
}

func (pm *ProtocolMixer) RemoveMode(mode ProtocolMode) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	newModes := make([]ProtocolMode, 0, len(pm.modes))
	for _, m := range pm.modes {
		if m != mode {
			newModes = append(newModes, m)
		}
	}

	if len(newModes) == 0 {
		return
	}

	pm.modes = newModes

	found := false
	for _, m := range pm.modes {
		if m == pm.currentMode {
			found = true
			break
		}
	}

	if !found {
		pm.currentMode = pm.modes[0]
		pm.currentMask = pm.factory.CreateMask(pm.currentMode)
		pm.lastSwitch = time.Now()
	}
}
