package shred

import (
	"crypto/rand"
	"encoding/binary"
	"sync"
	"time"
)

type Session struct {
	ID        uint64
	CreatedAt time.Time
	LastSeen  time.Time
	BytesIn   uint64
	BytesOut  uint64
	mu        sync.RWMutex
}

type SessionManager struct {
	sessions map[uint64]*Session
	mu       sync.RWMutex
}

func NewSessionManager() *SessionManager {
	return &SessionManager{
		sessions: make(map[uint64]*Session),
	}
}

func (sm *SessionManager) CreateSession() *Session {
	var id uint64
	binary.Read(rand.Reader, binary.BigEndian, &id)

	session := &Session{
		ID:        id,
		CreatedAt: time.Now(),
		LastSeen:  time.Now(),
	}

	sm.mu.Lock()
	sm.sessions[id] = session
	sm.mu.Unlock()

	return session
}

func (sm *SessionManager) GetSession(id uint64) *Session {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.sessions[id]
}

func (sm *SessionManager) UpdateActivity(id uint64) {
	sm.mu.RLock()
	session, exists := sm.sessions[id]
	sm.mu.RUnlock()

	if exists {
		session.mu.Lock()
		session.LastSeen = time.Now()
		session.mu.Unlock()
	}
}

func (sm *SessionManager) Cleanup(maxAge time.Duration) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	for id, session := range sm.sessions {
		if time.Since(session.LastSeen) > maxAge {
			delete(sm.sessions, id)
		}
	}
}
