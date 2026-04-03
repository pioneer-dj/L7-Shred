package engine

import (
	"sync"
	"time"
)

type ChaffScheduler struct {
	enabled     bool
	interval    time.Duration
	targets     []string
	stopChan    chan struct{}
	wg          sync.WaitGroup
	onChaffFunc func(target string)
}

func NewChaffScheduler(interval time.Duration, targets []string) *ChaffScheduler {
	return &ChaffScheduler{
		enabled:  true,
		interval: interval,
		targets:  targets,
		stopChan: make(chan struct{}),
	}
}

func (cs *ChaffScheduler) Start() {
	if !cs.enabled {
		return
	}

	cs.wg.Add(1)
	go func() {
		defer cs.wg.Done()
		ticker := time.NewTicker(cs.interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				cs.sendChaff()
			case <-cs.stopChan:
				return
			}
		}
	}()
}

func (cs *ChaffScheduler) sendChaff() {
	if cs.onChaffFunc == nil {
		return
	}

	target := cs.targets[time.Now().UnixNano()%int64(len(cs.targets))]
	cs.onChaffFunc(target)
}

func (cs *ChaffScheduler) Stop() {
	cs.enabled = false
	close(cs.stopChan)
	cs.wg.Wait()
}

func (cs *ChaffScheduler) SetChaffCallback(fn func(target string)) {
	cs.onChaffFunc = fn
}
