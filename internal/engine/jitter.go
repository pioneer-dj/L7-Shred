package engine

import (
	"math"
	"math/rand"
	"time"
)

type JitterEngine struct {
	meanMs   float64
	stdDevMs float64
	lossRate float64
	rng      *rand.Rand
}

func NewJitterEngine(meanMs, stdDevMs float64, lossRate float64) *JitterEngine {
	return &JitterEngine{
		meanMs:   meanMs,
		stdDevMs: stdDevMs,
		lossRate: lossRate,
		rng:      rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

func (j *JitterEngine) Apply() time.Duration {
	u1 := j.rng.Float64()
	u2 := j.rng.Float64()

	z0 := math.Sqrt(-2.0*math.Log(u1)) * math.Cos(2.0*math.Pi*u2)

	delayMs := j.meanMs + z0*j.stdDevMs
	if delayMs < 0 {
		delayMs = 0
	}

	delay := time.Duration(delayMs) * time.Millisecond
	time.Sleep(delay)

	return delay
}

func (j *JitterEngine) ShouldDrop() bool {
	return j.rng.Float64() < j.lossRate
}
