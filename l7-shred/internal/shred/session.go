package shred

import (
	"crypto/rand"
	"encoding/binary"
	"sync"
	"time"
)

type SessionState byte

const (
	SessionStateInit SessionState = iota
	SessionStateHandshakeSent
	SessionStateHandshakeReceived
	SessionStateEstablished
	SessionStateClosed
)

func (s SessionState) String() string {
	switch s {
	case SessionStateInit:
		return "init"
	case SessionStateHandshakeSent:
		return "handshake_sent"
	case SessionStateHandshakeReceived:
		return "handshake_received"
	case SessionStateEstablished:
		return "established"
	case SessionStateClosed:
		return "closed"
	default:
		return "unknown"
	}
}

type SessionConfig struct {
	SwitchInterval         time.Duration
	Modes                  []ProtocolMode
	EnableReplayProtection bool
	ReplayWindowSize       int
}

type Session struct {
	ID        uint64
	CreatedAt time.Time
	LastSeen  time.Time
	BytesIn   uint64
	BytesOut  uint64
	State     SessionState

	MaskConfig  *SessionConfig
	LocalMixer  *MaskMixer
	RemoteMixer *MaskMixer

	ReplaySeen   map[uint64]bool
	ReplayWindow []uint64
	ReplayMutex  sync.RWMutex

	mu sync.RWMutex
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

	config := &SessionConfig{
		SwitchInterval: 5 * time.Minute,
		Modes: []ProtocolMode{
			ModeMinecraft,
			ModeWebRTC,
			ModeQUIC,
			ModeRuTube,
		},
		EnableReplayProtection: true,
		ReplayWindowSize:       64,
	}

	session := &Session{
		ID:           id,
		CreatedAt:    time.Now(),
		LastSeen:     time.Now(),
		State:        SessionStateInit,
		MaskConfig:   config,
		ReplaySeen:   make(map[uint64]bool),
		ReplayWindow: make([]uint64, 0),
	}

	session.LocalMixer = NewMaskMixer(config.SwitchInterval)
	session.LocalMixer.SetModes(config.Modes)

	session.RemoteMixer = NewMaskMixer(config.SwitchInterval)
	session.RemoteMixer.SetModes(config.Modes)

	sm.mu.Lock()
	sm.sessions[id] = session
	sm.mu.Unlock()

	return session
}

func (sm *SessionManager) CreateSessionWithConfig(config *SessionConfig) *Session {
	var id uint64
	binary.Read(rand.Reader, binary.BigEndian, &id)

	session := &Session{
		ID:           id,
		CreatedAt:    time.Now(),
		LastSeen:     time.Now(),
		State:        SessionStateInit,
		MaskConfig:   config,
		ReplaySeen:   make(map[uint64]bool),
		ReplayWindow: make([]uint64, 0),
	}

	session.LocalMixer = NewMaskMixer(config.SwitchInterval)
	session.LocalMixer.SetModes(config.Modes)

	session.RemoteMixer = NewMaskMixer(config.SwitchInterval)
	session.RemoteMixer.SetModes(config.Modes)

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

func (sm *SessionManager) UpdateState(id uint64, state SessionState) {
	sm.mu.RLock()
	session, exists := sm.sessions[id]
	sm.mu.RUnlock()

	if exists {
		session.mu.Lock()
		session.State = state
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

func (s *Session) Wrap(payload []byte) []byte {
	s.mu.Lock()
	s.BytesOut += uint64(len(payload))
	s.mu.Unlock()

	return s.LocalMixer.Wrap(payload)
}

func (s *Session) Unwrap(data []byte) ([]byte, error) {
	s.mu.Lock()
	s.BytesIn += uint64(len(data))
	s.mu.Unlock()

	return s.RemoteMixer.Unwrap(data)
}

func (s *Session) CheckReplay(sequence uint64) bool {
	if !s.MaskConfig.EnableReplayProtection {
		return false
	}

	s.ReplayMutex.Lock()
	defer s.ReplayMutex.Unlock()

	if s.ReplaySeen[sequence] {
		return true
	}

	s.ReplaySeen[sequence] = true
	s.ReplayWindow = append(s.ReplayWindow, sequence)

	if len(s.ReplayWindow) > s.MaskConfig.ReplayWindowSize {
		oldest := s.ReplayWindow[0]
		delete(s.ReplaySeen, oldest)
		s.ReplayWindow = s.ReplayWindow[1:]
	}

	return false
}

func (s *Session) RotateLocalMask() {
	s.LocalMixer.ForceRotate()
}

func (s *Session) RotateRemoteMask() {
	s.RemoteMixer.ForceRotate()
}

func (s *Session) SyncModes() {
	s.mu.RLock()
	modes := s.MaskConfig.Modes
	interval := s.MaskConfig.SwitchInterval
	s.mu.RUnlock()

	s.LocalMixer.SetModes(modes)
	s.LocalMixer.SetSwitchInterval(interval)
	s.RemoteMixer.SetModes(modes)
	s.RemoteMixer.SetSwitchInterval(interval)
}

func (s *Session) GetStats() map[string]interface{} {
	stats := make(map[string]interface{})
	stats["id"] = s.ID
	stats["state"] = s.State.String()
	stats["created_at"] = s.CreatedAt
	stats["last_seen"] = s.LastSeen
	stats["bytes_in"] = s.BytesIn
	stats["bytes_out"] = s.BytesOut
	stats["local_mode"] = s.LocalMixer.GetCurrentMode().String()
	stats["remote_mode"] = s.RemoteMixer.GetCurrentMode().String()

	maskStats := s.LocalMixer.GetStats()
	stats["mask_stats"] = maskStats

	return stats
}
