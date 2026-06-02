package crypto

import (
	"crypto/rand"
	"math"
	"sync"
	"time"
)

type PaddingEngine struct {
	minSize      int
	maxSize      int
	currentSize  int
	lastRotate   time.Time
	rotateEvery  time.Duration
	mu           sync.RWMutex
	targetSizes  []int
	useHistogram bool
}

type PaddingConfig struct {
	MinSize        int
	MaxSize        int
	RotateInterval time.Duration
	UseHistogram   bool
	TargetSizes    []int
}

func DefaultPaddingConfig() *PaddingConfig {
	return &PaddingConfig{
		MinSize:        16,
		MaxSize:        256,
		RotateInterval: 30 * time.Second,
		UseHistogram:   true,
		TargetSizes: []int{
			40,   // TCP ACK
			52,   // TCP SYN-ACK
			64,   // DNS
			76,   // QUIC
			88,   // TLS record
			128,  // HTTP/2 frame
			256,  // Small packet
			512,  // Medium packet
			1024, // Large packet
			1350, // MTU typical
			1400, // MTU max
		},
	}
}

func NewPaddingEngine(config *PaddingConfig) *PaddingEngine {
	if config == nil {
		config = DefaultPaddingConfig()
	}

	engine := &PaddingEngine{
		minSize:      config.MinSize,
		maxSize:      config.MaxSize,
		rotateEvery:  config.RotateInterval,
		currentSize:  config.MinSize,
		targetSizes:  config.TargetSizes,
		useHistogram: config.UseHistogram,
	}
	engine.rotateIfNeeded()
	return engine
}

func (p *PaddingEngine) rotateIfNeeded() {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.rotateEvery > 0 && time.Since(p.lastRotate) > p.rotateEvery {
		if p.useHistogram && len(p.targetSizes) > 0 {
			// Выбираем размер из гистограммы реальных пакетов
			idx := int(time.Now().UnixNano() % int64(len(p.targetSizes)))
			p.currentSize = p.targetSizes[idx]
		} else {
			// Случайный размер в диапазоне
			rangeSize := p.maxSize - p.minSize
			if rangeSize > 0 {
				p.currentSize = p.minSize + int(time.Now().UnixNano()%int64(rangeSize))
			} else {
				p.currentSize = p.minSize
			}
		}
		p.lastRotate = time.Now()
	}
}

func (p *PaddingEngine) Generate() []byte {
	p.rotateIfNeeded()

	p.mu.RLock()
	size := p.currentSize
	p.mu.RUnlock()

	if size <= 0 {
		return nil
	}

	pad := make([]byte, size)
	rand.Read(pad)
	return pad
}

func (p *PaddingEngine) GenerateUpTo(maxLen int) []byte {
	p.rotateIfNeeded()

	p.mu.RLock()
	baseSize := p.currentSize
	p.mu.RUnlock()

	if baseSize <= 0 {
		return nil
	}

	actualSize := baseSize
	if actualSize > maxLen {
		actualSize = maxLen
	}

	pad := make([]byte, actualSize)
	rand.Read(pad)
	return pad
}

func (p *PaddingEngine) NormalizePacket(data []byte, targetLen int) []byte {
	if len(data) >= targetLen {
		return data
	}

	// Добавляем padding до целевой длины
	result := make([]byte, targetLen)
	copy(result, data)
	rand.Read(result[len(data):])
	return result
}

func (p *PaddingEngine) AddRandomPadding(data []byte, minPad, maxPad int) []byte {
	if minPad <= 0 || maxPad <= 0 || minPad > maxPad {
		return data
	}

	padLen := minPad
	if minPad != maxPad {
		rangeSize := maxPad - minPad
		padLen = minPad + int(time.Now().UnixNano()%int64(rangeSize))
	}

	if padLen <= 0 {
		return data
	}

	result := make([]byte, len(data)+padLen)
	copy(result, data)
	rand.Read(result[len(data):])
	return result
}

func (p *PaddingEngine) GetCurrentSize() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.currentSize
}

func (p *PaddingEngine) SetTargetSizes(sizes []int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.targetSizes = sizes
}

func (p *PaddingEngine) SetMinMax(min, max int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.minSize = min
	p.maxSize = max
	if p.currentSize < min {
		p.currentSize = min
	}
	if p.currentSize > max {
		p.currentSize = max
	}
}

func (p *PaddingEngine) GetStats() map[string]interface{} {
	p.mu.RLock()
	defer p.mu.RUnlock()

	return map[string]interface{}{
		"min_size":         p.minSize,
		"max_size":         p.maxSize,
		"current_size":     p.currentSize,
		"rotate_interval":  p.rotateEvery.String(),
		"use_histogram":    p.useHistogram,
		"target_sizes_len": len(p.targetSizes),
	}
}

// NewNormalizedPadding создает padding, который маскирует реальный размер пакета
// до ближайшего "естественного" размера из гистограммы
func (p *PaddingEngine) NewNormalizedPadding(originalLen int) []byte {
	p.rotateIfNeeded()

	p.mu.RLock()
	targets := p.targetSizes
	p.mu.RUnlock()

	// Находим ближайший целевой размер
	targetLen := p.findClosestTarget(originalLen, targets)
	if targetLen <= originalLen {
		targetLen = originalLen + p.minSize
	}

	padLen := targetLen - originalLen
	if padLen <= 0 {
		return nil
	}

	pad := make([]byte, padLen)
	rand.Read(pad)
	return pad
}

func (p *PaddingEngine) findClosestTarget(val int, targets []int) int {
	closest := targets[0]
	minDiff := math.MaxInt32

	for _, t := range targets {
		diff := t - val
		if diff >= 0 && diff < minDiff {
			minDiff = diff
			closest = t
		}
	}

	return closest
}
