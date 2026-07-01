package proto

import (
	"sync"
	"time"
)

type PacketEntry struct {
	Data     []byte
	SentAt   time.Time
	Attempts int
}

type ARQManager struct {
	sentPackets map[uint64]*PacketEntry
	nextSeq     uint64
	mu          sync.RWMutex
	rto         time.Duration
	maxRetries  int
	closeCh     chan struct{}
}

func NewARQManager() *ARQManager {
	return &ARQManager{
		sentPackets: make(map[uint64]*PacketEntry),
		nextSeq:     1,
		rto:         500 * time.Millisecond,
		maxRetries:  5,
		closeCh:     make(chan struct{}),
	}
}

func (a *ARQManager) NextSequence() uint64 {
	a.mu.Lock()
	defer a.mu.Unlock()
	seq := a.nextSeq
	a.nextSeq++
	return seq
}

func (a *ARQManager) StorePacket(seq uint64, data []byte) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.sentPackets[seq] = &PacketEntry{
		Data:     data,
		SentAt:   time.Now(),
		Attempts: 1,
	}
}

func (a *ARQManager) MarkAcked(seq uint64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.sentPackets, seq)
}

func (a *ARQManager) GetPacket(seq uint64) ([]byte, bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	entry, ok := a.sentPackets[seq]
	return entry.Data, ok
}

func (a *ARQManager) GetPendingForRetransmit() []uint64 {
	a.mu.RLock()
	defer a.mu.RUnlock()
	var pending []uint64
	for seq, entry := range a.sentPackets {
		if time.Since(entry.SentAt) > a.rto {
			pending = append(pending, seq)
		}
	}
	return pending
}

func (a *ARQManager) IncrementAttempt(seq uint64) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	entry, ok := a.sentPackets[seq]
	if !ok {
		return 0
	}
	entry.Attempts++
	entry.SentAt = time.Now()
	return entry.Attempts
}

func (a *ARQManager) ShouldDrop(seq uint64) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	entry, ok := a.sentPackets[seq]
	if !ok {
		return true
	}
	return entry.Attempts > a.maxRetries
}

func (a *ARQManager) StartRetransmitLoop(sendFunc func([]byte) error) {
	go func() {
		ticker := time.NewTicker(a.rto / 2)
		defer ticker.Stop()
		for {
			select {
			case <-a.closeCh:
				return
			case <-ticker.C:
				pending := a.GetPendingForRetransmit()
				for _, seq := range pending {
					if a.ShouldDrop(seq) {
						a.mu.Lock()
						delete(a.sentPackets, seq)
						a.mu.Unlock()
						continue
					}
					data, ok := a.GetPacket(seq)
					if !ok {
						continue
					}
					a.IncrementAttempt(seq)
					if err := sendFunc(data); err != nil {
						continue
					}
				}
			}
		}
	}()
}

func (a *ARQManager) Stop() {
	close(a.closeCh)
}
