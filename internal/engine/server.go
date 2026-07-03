package engine

import (
	"crypto/rand"
	"log"
	"net"
	"sync"
	"time"

	"github.com/l7-shred/core/internal/shred"
	"github.com/l7-shred/core/internal/transport"
	"github.com/l7-shred/core/internal/tun"
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
	tunDev         *tun.TunDevice
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
	writeMu   sync.Mutex
}

func NewServer(config *transport.Config) *Server {
	authKey := make([]byte, 32)
	if len(config.SecretKey) > 0 {
		authKey = []byte(config.SecretKey)
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
	tunDev, err := tun.NewTunDevice()
	if err != nil {
		s.logger.Printf("Failed to create TUN device: %v", err)
	} else {
		s.tunDev = tunDev
		s.logger.Printf("TUN device created")
		go s.tunLoop()
	}

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

func (s *Server) tunLoop() {
	s.logger.Printf("tunLoop started")
	for {
		select {
		case <-s.stopChan:
			return
		default:
		}

		data, err := s.tunDev.Read()
		if err != nil {
			s.logger.Printf("TUN read error: %v", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		if len(data) == 0 {
			continue
		}

		s.mu.RLock()
		for _, sc := range s.connections {
			wrapped := sc.Session.Wrap(data)
			sc.writeMu.Lock()
			err := writeFrame(sc.Conn, wrapped)
			sc.writeMu.Unlock()
			if err != nil {
				s.logger.Printf("Failed to write to client %d: %v", sc.ID, err)
			}
		}
		s.mu.RUnlock()
	}
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

	if tcpConn, ok := conn.(*net.TCPConn); ok {
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(30 * time.Second)
	}

	s.logger.Printf("New connection from %s", conn.RemoteAddr())

	config, err := s.handshakeMgr.PerformServerHandshake(conn)
	if err != nil {
		s.logger.Printf("Handshake failed from %s: %v", conn.RemoteAddr(), err)
		return
	}

	session := s.sessionManager.CreateSessionWithConfig(config)

	s.logger.Printf("Session %d established with modes: %v, current mode: %v, interval: %v",
		session.ID, config.Modes, config.CurrentMode, config.SwitchInterval)

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
	session.SyncModes()

	s.handleDataExchange(serverConn)
}

func (s *Server) handleDataExchange(sc *ServerConnection) {
	scratch := make([]byte, 65536)

	sc.Conn.SetReadDeadline(time.Time{})
	sc.Conn.SetWriteDeadline(time.Time{})

	for {
		select {
		case <-s.stopChan:
			return
		default:
		}

		data, err := readFrame(sc.Conn, scratch)
		if err != nil {
			s.logger.Printf("Read error from session %d: %v", sc.ID, err)
			return
		}

		sc.mu.Lock()
		sc.BytesIn += uint64(len(data))
		sc.LastSeen = time.Now()
		sc.mu.Unlock()

		s.sessionManager.UpdateActivity(sc.ID)

		unwrapped, err := sc.Session.Unwrap(data)
		if err != nil {
			s.logger.Printf("Unwrap error from session %d: %v", sc.ID, err)
			continue
		}

		if len(unwrapped) < 20 {
			continue
		}

		version := (unwrapped[0] >> 4) & 0x0F
		if version != 4 && version != 6 {
			continue
		}

		if version == 4 {
			headerLen := int(unwrapped[0]&0x0F) * 4
			if len(unwrapped) < headerLen {
				continue
			}
		}

		if s.tunDev != nil {
			if err := s.tunDev.Write(unwrapped); err != nil {
				s.logger.Printf("TUN write error: %v", err)
			}
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

	sc.writeMu.Lock()
	err := writeFrame(sc.Conn, wrapped)
	sc.writeMu.Unlock()

	sc.mu.Lock()
	sc.BytesOut += uint64(len(wrapped))
	sc.LastSeen = time.Now()
	sc.mu.Unlock()
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
		s.inbound.Stop()
	}

	if s.tunDev != nil {
		s.tunDev.Close()
	}

	return nil
}

func (s *Server) GetAuthKey() []byte {
	return s.authKey
}