package shred

import (
	"sync"
	"time"
)

type TrafficShaper struct {
	burstSize  int
	minBurst   int
	maxBurst   int
	interBurst time.Duration
	queue      chan []byte
	mu         sync.Mutex
	active     bool
}

func NewTrafficShaper(minBurst, maxBurst int, interBurst time.Duration) *TrafficShaper {
	return &TrafficShaper{
		minBurst:   minBurst,
		maxBurst:   maxBurst,
		interBurst: interBurst,
		queue:      make(chan []byte, 1000),
		active:     true,
	}
}

func (ts *TrafficShaper) Process(data []byte) [][]byte {
	var bursts [][]byte
	remaining := data

	for len(remaining) > 0 {
		burstSize := ts.minBurst
		if ts.maxBurst > ts.minBurst {
			burstSize = ts.minBurst + int(time.Now().UnixNano()%int64(ts.maxBurst-ts.minBurst))
		}
		if burstSize > len(remaining) {
			burstSize = len(remaining)
		}

		burst := make([]byte, burstSize)
		copy(burst, remaining[:burstSize])
		bursts = append(bursts, burst)
		remaining = remaining[burstSize:]
	}

	return bursts
}

func (ts *TrafficShaper) Start() {
	go func() {
		for ts.active {
			time.Sleep(ts.interBurst)
		}
	}()
}

func (ts *TrafficShaper) Stop() {
	ts.active = false
}
