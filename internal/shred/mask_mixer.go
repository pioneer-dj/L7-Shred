package shred

import (
	"log"
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
	ModeOzon
	ModeWildberries
	ModeSberID
	ModeGosuslugi
	ModeTLS
	ModeBrowser
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
	case ModeOzon:
		return "ozon"
	case ModeWildberries:
		return "wildberries"
	case ModeSberID:
		return "sberid"
	case ModeGosuslugi:
		return "gosuslugi"
	case ModeTLS:
		return "tls"
	case ModeBrowser:
		return "browser"
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
	case ModeOzon:
		return masks.NewOzonMask()
	case ModeWildberries:
		return masks.NewWildberriesMask()
	case ModeSberID:
		return masks.NewSberIDMask()
	case ModeGosuslugi:
		return masks.NewGosuslugiMask()
	case ModeTLS:
		return masks.NewTLSMask()
	case ModeBrowser:
		return masks.NewBrowserMask()
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
	selector         *masks.MaskSelector
	timeBasedEnabled bool
	isDayModeActive  bool
	dayModes         []ProtocolMode
	nightModes       []ProtocolMode
}

func getHourOfDay() int {
	return time.Now().Hour()
}

func isDayTime() bool {
	hour := getHourOfDay()
	return hour >= 8 && hour < 23
}

func NewMaskMixer(switchInterval time.Duration) *MaskMixer {
	dayModes := []ProtocolMode{
		ModeVK,
		ModeYandex,
		ModeOzon,
		ModeWildberries,
		ModeSberID,
		ModeGosuslugi,
		ModeWebRTC,
		ModeQUIC,
		ModeTLS,
	}

	nightModes := []ProtocolMode{
		ModeRuTube,
		ModeTLS,
		ModeQUIC,
		ModeWebRTC,
		ModeVK,
	}

	var modes []ProtocolMode
	var isDayModeActive bool
	if isDayTime() {
		modes = dayModes
		isDayModeActive = true
	} else {
		modes = nightModes
		isDayModeActive = false
	}

	mixer := &MaskMixer{
		modes:            modes,
		switchInterval:   switchInterval,
		lastSwitch:       time.Now(),
		currentMode:      modes[0],
		factory:          NewMaskFactory(),
		mu:               make(chan struct{}, 1),
		stats:            make(map[ProtocolMode]int64),
		selector:         masks.NewMaskSelector(),
		timeBasedEnabled: true,
		isDayModeActive:  isDayModeActive,
		dayModes:         dayModes,
		nightModes:       nightModes,
	}

	mixer.currentMask = mixer.factory.CreateMask(mixer.currentMode)

	return mixer
}

func (m *MaskMixer) lock() {
	m.mu <- struct{}{}
}

func (m *MaskMixer) unlock() {
	<-m.mu
}

func (m *MaskMixer) SelectMask(payload []byte) ProtocolMode {
	if len(payload) >= 5 && payload[0] == 0x16 && payload[1] == 0x03 {
		return ModeBrowser
	}
	return m.GetCurrentMode()
}

func (m *MaskMixer) checkTimeBasedRotation() {
	if !m.timeBasedEnabled {
		return
	}

	currentIsDay := isDayTime()

	if currentIsDay && !m.isDayModeActive {
		m.modes = m.dayModes
		m.isDayModeActive = true
		m.currentMode = m.modes[0]
		m.currentMask = m.factory.CreateMask(m.currentMode)
		m.lastSwitch = time.Now()
		log.Printf("[MaskMixer] Time-based rotation: switched to DAY mode (hour: %d)", getHourOfDay())
	} else if !currentIsDay && m.isDayModeActive {
		m.modes = m.nightModes
		m.isDayModeActive = false
		m.currentMode = m.modes[0]
		m.currentMask = m.factory.CreateMask(m.currentMode)
		m.lastSwitch = time.Now()
		log.Printf("[MaskMixer] Time-based rotation: switched to NIGHT mode (hour: %d)", getHourOfDay())
	}
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
	m.timeBasedEnabled = false
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

	m.checkTimeBasedRotation()

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
	mode := m.SelectMask(payload)
	mask := m.factory.CreateMask(mode)

	m.lock()
	m.packetsWrapped++
	m.stats[mode]++
	m.unlock()

	return mask.Wrap(payload)
}

func (m *MaskMixer) Unwrap(data []byte) ([]byte, error) {
	m.lock()
	defer m.unlock()

	result, err := m.currentMask.Unwrap(data)
	if err == nil {
		m.packetsUnwrapped++
		return result, nil
	}

	for _, mode := range m.modes {
		testMask := m.factory.CreateMask(mode)
		result, err := testMask.Unwrap(data)
		if err == nil {
			m.currentMode = mode
			m.currentMask = testMask
			m.packetsUnwrapped++
			return result, nil
		}
	}

	m.errorsCount++
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
	stats["time_based_enabled"] = m.timeBasedEnabled
	stats["is_daytime"] = isDayTime()
	stats["current_hour"] = getHourOfDay()

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

func (m *MaskMixer) GetSwitchInterval() time.Duration {
	m.lock()
	defer m.unlock()
	return m.switchInterval
}

func (m *MaskMixer) SelectMaskForDomain(domain string) string {
	if m.selector == nil {
		return "webrtc"
	}
	return m.selector.Select(domain)
}

func (m *MaskMixer) SetCurrentMode(mode ProtocolMode) {
	m.lock()
	defer m.unlock()

	m.currentMode = mode
	m.currentMask = m.factory.CreateMask(mode)
	log.Printf("[MaskMixer] Set current mode to %s", mode.String())
}

func (m *MaskMixer) SwitchToDomain(domain string) {
	m.lock()
	defer m.unlock()

	maskName := m.SelectMaskForDomain(domain)

	var newMode ProtocolMode
	switch maskName {
	case "vk":
		newMode = ModeVK
	case "rutube":
		newMode = ModeRuTube
	case "yandex":
		newMode = ModeYandex
	case "ozon":
		newMode = ModeOzon
	case "wildberries":
		newMode = ModeWildberries
	case "sberid":
		newMode = ModeSberID
	case "gosuslugi":
		newMode = ModeGosuslugi
	case "tls":
		newMode = ModeTLS
	case "quic":
		newMode = ModeQUIC
	case "webrtc":
		fallthrough
	default:
		newMode = ModeWebRTC
	}

	if m.currentMode == newMode {
		return
	}

	m.currentMode = newMode
	m.currentMask = m.factory.CreateMask(newMode)
	log.Printf("[MaskMixer] Switched to %s for domain %s", m.currentMode.String(), domain)
}