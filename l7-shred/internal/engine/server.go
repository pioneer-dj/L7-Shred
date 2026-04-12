package engine

import (
	"crypto/rand"
	"log"
	"net"
	"sync"
	"time"

	"github.com/l7-shred/core/internal/shred"
	"github.com/l7-shred/core/internal/transport"
)

type Server struct {
	config         *transport.Config
	inbound        *transport.Inbound
	sessionManager *shred.SessionManager
	handshakeMgr   *shred.HandshakeManager
	authKey        []byte
	connections    map[uint64]*ServerConnection
	mu             sync.RWMutex
	logger         *log.Logger
	stopChan       chan struct{}
}

type ServerConnection struct {
	ID        uint64
	Conn      net.Conn
	Session   *shred.Session
	StartTime time.Time
	LastSeen  time.Time
	BytesIn   uint64
	BytesOut  uint64
	mu        sync.RWMutex
}

func NewServer(config *transport.Config) *Server {
	authKey := make([]byte, 32)
	if len(config.SecretKey) > 0 {
		authKey = config.SecretKey
	} else {
		rand.Read(authKey)
	}

	return &Server{
		config:         config,
		sessionManager: shred.NewSessionManager(),
		handshakeMgr:   shred.NewHandshakeManager(authKey, 10*time.Second),
		authKey:        authKey,
		connections:    make(map[uint64]*ServerConnection),
		stopChan:       make(chan struct{}),
		logger:         log.Default(),
	}
}

func (s *Server) SetLogger(logger *log.Logger) {
	s.logger = logger
}

func (s *Server) Start() error {
	inbound, err := transport.NewInbound(s.config)
	if err != nil {
		return err
	}

	s.inbound = inbound

	go s.acceptLoop()
	go s.cleanupLoop()

	s.logger.Printf("Server started on %s", s.config.ListenAddr)
	return s.inbound.Start()
}

func (s *Server) acceptLoop() {
	for {
		select {
		case <-s.stopChan:
			return
		default:
		}

		conn, err := s.inbound.Accept()
		if err != nil {
			s.logger.Printf("Accept error: %v", err)
			continue
		}

		go s.handleConnection(conn)
	}
}

func (s *Server) handleConnection(conn net.Conn) {
	defer conn.Close()

	s.logger.Printf("New connection from %s", conn.RemoteAddr())

	config, err := s.handshakeMgr.PerformServerHandshake(conn)
	if err != nil {
		s.logger.Printf("Handshake failed from %s: %v", conn.RemoteAddr(), err)
		return
	}

	session := s.sessionManager.CreateSessionWithConfig(config)

	serverConn := &ServerConnection{
		ID:        session.ID,
		Conn:      conn,
		Session:   session,
		StartTime: time.Now(),
		LastSeen:  time.Now(),
	}

	s.mu.Lock()
	s.connections[session.ID] = serverConn
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		delete(s.connections, session.ID)
		s.mu.Unlock()
		s.logger.Printf("Connection closed from %s, session %d", conn.RemoteAddr(), session.ID)
	}()

	session.State = shred.SessionStateEstablished
	s.logger.Printf("Session %d established with modes: %v, interval: %v",
		session.ID, config.Modes, config.SwitchInterval)

	s.handleDataExchange(serverConn)
}

func (s *Server) handleDataExchange(sc *ServerConnection) {
	buf := make([]byte, 65536)

	for {
		select {
		case <-s.stopChan:
			return
		default:
		}

		sc.Conn.SetReadDeadline(time.Now().Add(30 * time.Second))

		n, err := sc.Conn.Read(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			s.logger.Printf("Read error from session %d: %v", sc.ID, err)
			return
		}

		data := buf[:n]

		sc.mu.Lock()
		sc.BytesIn += uint64(n)
		sc.LastSeen = time.Now()
		sc.mu.Unlock()

		s.sessionManager.UpdateActivity(sc.ID)

		unwrapped, err := sc.Session.Unwrap(data)
		if err != nil {
			s.logger.Printf("Unwrap error from session %d: %v", sc.ID, err)
			continue
		}

		if len(unwrapped) > 0 {
			s.logger.Printf("Received %d bytes from session %d", len(unwrapped), sc.ID)
		}
	}
}

func (s *Server) SendToSession(sessionID uint64, data []byte) error {
	s.mu.RLock()
	sc, exists := s.connections[sessionID]
	s.mu.RUnlock()

	if !exists {
		return ErrSessionNotFound
	}

	wrapped := sc.Session.Wrap(data)

	sc.mu.Lock()
	defer sc.mu.Unlock()

	sc.BytesOut += uint64(len(wrapped))
	sc.LastSeen = time.Now()
	_, err := sc.Conn.Write(wrapped)
	return err
}

func (s *Server) Broadcast(data []byte) {
	s.mu.RLock()
	connections := make([]*ServerConnection, 0, len(s.connections))
	for _, conn := range s.connections {
		connections = append(connections, conn)
	}
	s.mu.RUnlock()

	for _, sc := range connections {
		go func(sc *ServerConnection) {
			s.SendToSession(sc.ID, data)
		}(sc)
	}
}

func (s *Server) GetSession(sessionID uint64) *shred.Session {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if sc, exists := s.connections[sessionID]; exists {
		return sc.Session
	}
	return nil
}

func (s *Server) GetConnection(sessionID uint64) *ServerConnection {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.connections[sessionID]
}

func (s *Server) GetAllSessions() []*shred.Session {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sessions := make([]*shred.Session, 0, len(s.connections))
	for _, conn := range s.connections {
		sessions = append(sessions, conn.Session)
	}
	return sessions
}

func (s *Server) GetStats() map[string]interface{} {
	s.mu.RLock()
	defer s.mu.RUnlock()

	stats := make(map[string]interface{})
	stats["active_connections"] = len(s.connections)

	var totalBytesIn, totalBytesOut uint64
	sessionStats := make([]map[string]interface{}, 0)

	for _, sc := range s.connections {
		sc.mu.RLock()
		sessionStat := map[string]interface{}{
			"id":         sc.ID,
			"start_time": sc.StartTime,
			"duration":   time.Since(sc.StartTime).String(),
			"bytes_in":   sc.BytesIn,
			"bytes_out":  sc.BytesOut,
			"last_seen":  sc.LastSeen,
			"state":      sc.Session.State.String(),
			"local_mode": sc.Session.LocalMixer.GetCurrentMode().String(),
		}
		sessionStats = append(sessionStats, sessionStat)
		totalBytesIn += sc.BytesIn
		totalBytesOut += sc.BytesOut
		sc.mu.RUnlock()
	}

	stats["total_bytes_in"] = totalBytesIn
	stats["total_bytes_out"] = totalBytesOut
	stats["sessions"] = sessionStats

	return stats
}

func (s *Server) cleanupLoop() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-s.stopChan:
			return
		case <-ticker.C:
			s.sessionManager.Cleanup(10 * time.Minute)

			s.mu.Lock()
			for id, sc := range s.connections {
				sc.mu.RLock()
				idle := time.Since(sc.LastSeen) > 10*time.Minute
				sc.mu.RUnlock()

				if idle {
					sc.Conn.Close()
					delete(s.connections, id)
					s.logger.Printf("Cleaned up inactive session %d", id)
				}
			}
			s.mu.Unlock()
		}
	}
}

func (s *Server) ForceRotateSession(sessionID uint64) error {
	session := s.GetSession(sessionID)
	if session == nil {
		return ErrSessionNotFound
	}
	session.RotateLocalMask()
	s.logger.Printf("Forced rotation for session %d", sessionID)
	return nil
}

func (s *Server) SetSessionModes(sessionID uint64, modes []shred.ProtocolMode) error {
	session := s.GetSession(sessionID)
	if session == nil {
		return ErrSessionNotFound
	}
	session.MaskConfig.Modes = modes
	session.SyncModes()
	s.logger.Printf("Updated modes for session %d: %v", sessionID, modes)
	return nil
}

func (s *Server) Stop() error {
	close(s.stopChan)

	s.mu.RLock()
	connections := make([]*ServerConnection, 0, len(s.connections))
	for _, conn := range s.connections {
		connections = append(connections, conn)
	}
	s.mu.RUnlock()

	for _, sc := range connections {
		sc.Conn.Close()
	}

	if s.inbound != nil {
		return s.inbound.Stop()
	}
	return nil
}

func (s *Server) GetAuthKey() []byte {
	return s.authKey
}
