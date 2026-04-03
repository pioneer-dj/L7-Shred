package utils

import (
	"math"
	"time"
)

type TimingJitter struct {
	meanMs   float64
	stdDevMs float64
	seed     int64
}

func NewTimingJitter(meanMs, stdDevMs float64) *TimingJitter {
	return &TimingJitter{
		meanMs:   meanMs,
		stdDevMs: stdDevMs,
		seed:     time.Now().UnixNano(),
	}
}

func (t *TimingJitter) NextDelay() time.Duration {
	u1 := float64(time.Now().UnixNano()%1000000) / 1000000.0
	u2 := float64(time.Now().UnixNano()%1000000) / 1000000.0

	z0 := math.Sqrt(-2.0*math.Log(u1)) * math.Cos(2.0*math.Pi*u2)

	delayMs := t.meanMs + z0*t.stdDevMs
	if delayMs < 0 {
		delayMs = 0
	}

	return time.Duration(delayMs) * time.Millisecond
}

func (t *TimingJitter) Sleep() {
	time.Sleep(t.NextDelay())
}
