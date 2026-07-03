package shred

import (
	"io"
	"time"
)

type ShredEngineConfig struct {
	MinFragmentSize    int
	MaxFragmentSize    int
	JitterBaseDelay    time.Duration
	JitterVariation    time.Duration
	JitterDropRate     float64
	ShaperMinBurst     int
	ShaperMaxBurst     int
	ShaperInterval     time.Duration
	MaskSwitchInterval time.Duration
	EnableMasking      bool
	Modes              []ProtocolMode
}

func DefaultShredEngineConfig() *ShredEngineConfig {
	return &ShredEngineConfig{
		MinFragmentSize:    32,
		MaxFragmentSize:    288,
		JitterBaseDelay:    5 * time.Millisecond,
		JitterVariation:    3 * time.Millisecond,
		JitterDropRate:     0.001,
		ShaperMinBurst:     500,
		ShaperMaxBurst:     1500,
		ShaperInterval:     10 * time.Millisecond,
		MaskSwitchInterval: 5 * time.Minute,
		EnableMasking:      true,
		Modes: []ProtocolMode{
			ModeVK,
			ModeRuTube,
			ModeYandex,
			ModeOzon,
			ModeWildberries,
			ModeSberID,
			ModeGosuslugi,
			ModeWebRTC,
			ModeQUIC,
			ModeTLS,
		},
	}
}

type ShredEngine struct {
	fragmentor *Fragmentor
	jitter     *TemporalJitter
	shaper     *TrafficShaper
	mixer      *MaskMixer
	config     *ShredEngineConfig
}

func NewShredEngine(config *ShredEngineConfig) *ShredEngine {
	if config == nil {
		config = DefaultShredEngineConfig()
	}

	engine := &ShredEngine{
		fragmentor: NewFragmentor(config.MinFragmentSize, config.MaxFragmentSize),
		jitter:     NewTemporalJitter(config.JitterBaseDelay, config.JitterVariation, config.JitterDropRate),
		shaper:     NewTrafficShaper(config.ShaperMinBurst, config.ShaperMaxBurst, config.ShaperInterval),
		config:     config,
	}

	if config.EnableMasking {
		engine.mixer = NewMaskMixer(config.MaskSwitchInterval)
		if len(config.Modes) > 0 {
			engine.mixer.SetModes(config.Modes)
		}
	}

	return engine
}

func (s *ShredEngine) Process(reader io.Reader, writer io.Writer) error {
	buf := make([]byte, 65536)

	for {
		n, err := reader.Read(buf)
		if err != nil {
			return err
		}

		data := buf[:n]

		if s.config.EnableMasking && s.mixer != nil {
			data = s.mixer.Wrap(data)
		}

		bursts := s.shaper.Process(data)

		for _, burst := range bursts {
			fragments := s.fragmentor.Fragment(burst)

			for _, fragment := range fragments {
				if _, err := writer.Write(fragment); err != nil {
					return err
				}

				s.jitter.Apply()

				if s.jitter.ShouldDrop() {
					s.jitter.SimulatePacketLoss()
				}
			}
		}
	}
}

func (s *ShredEngine) ProcessWithUnwrap(reader io.Reader, writer io.Writer) error {
	buf := make([]byte, 65536)

	for {
		n, err := reader.Read(buf)
		if err != nil {
			return err
		}

		data := buf[:n]

		if s.config.EnableMasking && s.mixer != nil {
			unwrapped, err := s.mixer.Unwrap(data)
			if err != nil {
				continue
			}
			data = unwrapped
		}

		if _, err := writer.Write(data); err != nil {
			return err
		}
	}
}

func (s *ShredEngine) GetStats() map[string]interface{} {
	stats := make(map[string]interface{})

	if s.mixer != nil {
		stats["masking"] = s.mixer.GetStats()
	}

	stats["fragmentor_enabled"] = s.fragmentor != nil
	stats["jitter_enabled"] = s.jitter != nil
	stats["shaper_enabled"] = s.shaper != nil

	return stats
}

func (s *ShredEngine) ForceRotate() {
	if s.mixer != nil {
		s.mixer.ForceRotate()
	}
}

func (s *ShredEngine) SetModes(modes []ProtocolMode) {
	s.config.Modes = modes
	if s.mixer != nil {
		s.mixer.SetModes(modes)
	}
}

func (s *ShredEngine) AddMode(mode ProtocolMode) {
	if s.mixer != nil {
		s.mixer.AddMode(mode)
	}

	for _, existing := range s.config.Modes {
		if existing == mode {
			return
		}
	}
	s.config.Modes = append(s.config.Modes, mode)
}

func (s *ShredEngine) RemoveMode(mode ProtocolMode) {
	if s.mixer != nil {
		s.mixer.RemoveMode(mode)
	}

	newModes := make([]ProtocolMode, 0, len(s.config.Modes))
	for _, existing := range s.config.Modes {
		if existing != mode {
			newModes = append(newModes, existing)
		}
	}
	s.config.Modes = newModes
}

func (s *ShredEngine) GetModes() []ProtocolMode {
	if s.mixer != nil {
		return s.mixer.GetModes()
	}
	return s.config.Modes
}

func (s *ShredEngine) EnableMasking(enable bool) {
	s.config.EnableMasking = enable
}

func (s *ShredEngine) SetSwitchInterval(interval time.Duration) {
	s.config.MaskSwitchInterval = interval
	if s.mixer != nil {
		s.mixer.SetSwitchInterval(interval)
	}
}
