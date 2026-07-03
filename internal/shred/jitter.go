package shred

import (
	"math/rand"
	"time"
)

type TemporalJitter struct {
	meanDelay   time.Duration
	stdDev      time.Duration
	lossRate    float64
	correlation float64
	lastDelay   time.Duration
	rng         *rand.Rand
}

func NewTemporalJitter(meanDelay, stdDev time.Duration, lossRate float64) *TemporalJitter {
	return &TemporalJitter{
		meanDelay: meanDelay,
		stdDev:    stdDev,
		lossRate:  lossRate,
		rng:       rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

func (tj *TemporalJitter) Apply() time.Duration {
	delay := tj.meanDelay + time.Duration(tj.rng.NormFloat64()*float64(tj.stdDev))
	if delay < 0 {
		delay = 0
	}

	tj.lastDelay = delay
	time.Sleep(delay)
	return delay
}

func (tj *TemporalJitter) ShouldDrop() bool {
	return tj.rng.Float64() < tj.lossRate
}

func (tj *TemporalJitter) SimulatePacketLoss() {
	if tj.ShouldDrop() {
		time.Sleep(100 * time.Millisecond)
	}
}
