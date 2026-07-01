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

func (ts *TrafficShaper) Process(data []byte, emit func(*PooledBuffer)) {
	ts.ProcessWithCallback(data, emit)
}

func (ts *TrafficShaper) ProcessWithCallback(data []byte, emit func(*PooledBuffer)) {
	remaining := data

	for len(remaining) > 0 {
		burstSize := ts.minBurst
		if ts.maxBurst > ts.minBurst {
			burstSize = ts.minBurst + int(time.Now().UnixNano()%int64(ts.maxBurst-ts.minBurst))
		}
		if burstSize > len(remaining) {
			burstSize = len(remaining)
		}

		buffer := GetPooledBuffer()
		copy(buffer.buf[:burstSize], remaining[:burstSize])
		buffer.length = burstSize
		emit(buffer)
		remaining = remaining[burstSize:]
	}
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
