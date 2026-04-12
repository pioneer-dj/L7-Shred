package shred

import (
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

type MaskFactory struct{}

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
	case ModeMinecraft:
		return masks.NewMinecraftMask()
	default:
		return masks.NewVKMask()
	}
}

type MaskMixer struct {
	currentMode      ProtocolMode
	currentMask      masks.Masker
	modes            []ProtocolMode
	lastSwitch       time.Time
	switchInterval   time.Duration
	factory          *MaskFactory
	mu               chan struct{}
	stats            map[ProtocolMode]int64
	packetsWrapped   int64
	packetsUnwrapped int64
	errorsCount      int64
}

func NewMaskMixer(switchInterval time.Duration) *MaskMixer {
	modes := []ProtocolMode{
		ModeMinecraft,
		ModeWebRTC,
		ModeQUIC,
		ModeRuTube,
		ModeYandex,
		ModeVK,
	}

	mixer := &MaskMixer{
		modes:          modes,
		switchInterval: switchInterval,
		lastSwitch:     time.Now(),
		currentMode:    modes[0],
		factory:        NewMaskFactory(),
		mu:             make(chan struct{}, 1),
		stats:          make(map[ProtocolMode]int64),
	}

	mixer.mu <- struct{}{}
	mixer.currentMask = mixer.factory.CreateMask(mixer.currentMode)
	<-mixer.mu

	return mixer
}

func (m *MaskMixer) lock() {
	m.mu <- struct{}{}
}

func (m *MaskMixer) unlock() {
	<-m.mu
}

func (m *MaskMixer) SetModes(modes []ProtocolMode) {
	m.lock()
	defer m.unlock()

	if len(modes) == 0 {
		return
	}

	m.modes = make([]ProtocolMode, len(modes))
	copy(m.modes, modes)
	m.currentMode = modes[0]
	m.currentMask = m.factory.CreateMask(m.currentMode)
	m.lastSwitch = time.Now()

	m.stats = make(map[ProtocolMode]int64)
	m.packetsWrapped = 0
	m.packetsUnwrapped = 0
	m.errorsCount = 0
}

func (m *MaskMixer) AddMode(mode ProtocolMode) {
	m.lock()
	defer m.unlock()

	for _, existing := range m.modes {
		if existing == mode {
			return
		}
	}

	m.modes = append(m.modes, mode)
}

func (m *MaskMixer) RemoveMode(mode ProtocolMode) {
	m.lock()
	defer m.unlock()

	newModes := make([]ProtocolMode, 0, len(m.modes))
	for _, existing := range m.modes {
		if existing != mode {
			newModes = append(newModes, existing)
		}
	}

	if len(newModes) == 0 {
		return
	}

	m.modes = newModes

	found := false
	for _, existing := range m.modes {
		if existing == m.currentMode {
			found = true
			break
		}
	}

	if !found {
		m.currentMode = m.modes[0]
		m.currentMask = m.factory.CreateMask(m.currentMode)
		m.lastSwitch = time.Now()
	}
}

func (m *MaskMixer) GetModes() []ProtocolMode {
	m.lock()
	defer m.unlock()

	modes := make([]ProtocolMode, len(m.modes))
	copy(modes, m.modes)
	return modes
}

func (m *MaskMixer) GetCurrentMode() ProtocolMode {
	m.lock()
	defer m.unlock()
	return m.currentMode
}

func (m *MaskMixer) GetCurrentMask() masks.Masker {
	m.lock()
	defer m.unlock()

	if m.switchInterval > 0 && time.Since(m.lastSwitch) > m.switchInterval {
		m.rotate()
	}

	return m.currentMask
}

func (m *MaskMixer) rotate() {
	if len(m.modes) == 0 {
		return
	}

	currentIndex := -1
	for i, mode := range m.modes {
		if mode == m.currentMode {
			currentIndex = i
			break
		}
	}

	nextIndex := (currentIndex + 1) % len(m.modes)
	newMode := m.modes[nextIndex]
	newMask := m.factory.CreateMask(newMode)

	m.currentMode = newMode
	m.currentMask = newMask
	m.lastSwitch = time.Now()
}

func (m *MaskMixer) Wrap(payload []byte) []byte {
	mask := m.GetCurrentMask()

	m.lock()
	m.packetsWrapped++
	m.stats[m.currentMode]++
	m.unlock()

	return mask.Wrap(payload)
}

func (m *MaskMixer) Unwrap(data []byte) ([]byte, error) {
	mask := m.GetCurrentMask()
	result, err := mask.Unwrap(data)
	if err == nil {
		m.lock()
		m.packetsUnwrapped++
		m.unlock()
		return result, nil
	}

	m.lock()
	modes := make([]ProtocolMode, len(m.modes))
	copy(modes, m.modes)
	m.unlock()

	for _, mode := range modes {
		testMask := m.factory.CreateMask(mode)
		result, err := testMask.Unwrap(data)
		if err == nil {
			m.lock()
			m.currentMode = mode
			m.currentMask = testMask
			m.packetsUnwrapped++
			m.unlock()
			return result, nil
		}
	}

	m.lock()
	m.errorsCount++
	m.unlock()

	return nil, masks.ErrUnwrapFailed
}

func (m *MaskMixer) ForceRotate() {
	m.lock()
	defer m.unlock()
	m.rotate()
}

func (m *MaskMixer) GetStats() map[string]interface{} {
	m.lock()
	defer m.unlock()

	stats := make(map[string]interface{})
	stats["current_mode"] = m.currentMode.String()
	stats["packets_wrapped"] = m.packetsWrapped
	stats["packets_unwrapped"] = m.packetsUnwrapped
	stats["errors"] = m.errorsCount
	stats["total_modes"] = len(m.modes)

	if m.switchInterval > 0 {
		stats["next_rotation"] = time.Until(m.lastSwitch.Add(m.switchInterval)).String()
		stats["switch_interval"] = m.switchInterval.String()
	}

	modeStats := make(map[string]int64)
	for mode, count := range m.stats {
		modeStats[mode.String()] = count
	}
	stats["mode_stats"] = modeStats

	return stats
}

func (m *MaskMixer) SetSwitchInterval(interval time.Duration) {
	m.lock()
	defer m.unlock()
	m.switchInterval = interval
}
