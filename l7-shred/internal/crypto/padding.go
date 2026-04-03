package crypto

import (
	"crypto/rand"
	"time"
)

type PaddingEngine struct {
	minSize     int
	maxSize     int
	currentSize int
	lastRotate  time.Time
	rotateEvery time.Duration
}

func NewPaddingEngine(minSize, maxSize int) *PaddingEngine {
	return &PaddingEngine{
		minSize:     minSize,
		maxSize:     maxSize,
		rotateEvery: 30 * time.Second,
		currentSize: minSize + (maxSize-minSize)/2,
	}
}

func (p *PaddingEngine) Generate() []byte {
	p.rotateIfNeeded()

	pad := make([]byte, p.currentSize)
	rand.Read(pad)

	return pad
}

func (p *PaddingEngine) rotateIfNeeded() {
	if time.Since(p.lastRotate) > p.rotateEvery {
		rangeSize := p.maxSize - p.minSize
		p.currentSize = p.minSize + int(time.Now().UnixNano()%int64(rangeSize))
		p.lastRotate = time.Now()
	}
}
