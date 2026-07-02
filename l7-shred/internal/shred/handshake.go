package shred

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"log"
	"net"
	"sync"
	"time"
)

var (
	ErrInvalidHandshakeMagic     = errors.New("invalid handshake magic")
	ErrInvalidHandshakeVersion   = errors.New("unsupported handshake version")
	ErrHandshakeChecksumMismatch = errors.New("handshake checksum mismatch")
	ErrAuthFailed                = errors.New("authentication failed")
	ErrHandshakeTimeout          = errors.New("handshake timeout")
	ErrHandshakeReplay           = errors.New("handshake replay detected")
)

type HandshakeType byte

const (
	HandshakeSyn HandshakeType = 0x01
	HandshakeAck HandshakeType = 0x02
	HandshakeFin HandshakeType = 0x03
)

type Handshake struct {
	Magic          [4]byte
	Type           HandshakeType
	Version        byte
	SwitchInterval uint32
	ModesCount     byte
	Modes          []ProtocolMode
	CurrentMode    uint32
	Timestamp      uint64
	Nonce          [16]byte
	Sequence       uint64
	Checksum       byte
}

func NewHandshake(sessionType HandshakeType, interval time.Duration, modes []ProtocolMode, currentMode ProtocolMode, sequence uint64) *Handshake {
	hs := &Handshake{
		Magic:          [4]byte{0xDE, 0xAD, 0xBE, 0xEF},
		Type:           sessionType,
		Version:        1,
		SwitchInterval: uint32(interval.Seconds()),
		ModesCount:     byte(len(modes)),
		Modes:          modes,
		CurrentMode:    uint32(currentMode),
		Timestamp:      uint64(time.Now().UnixNano()),
		Sequence:       sequence,
	}
	rand.Read(hs.Nonce[:])
	hs.Checksum = hs.calcChecksum()
	return hs
}

func (h *Handshake) calcChecksum() byte {
	var sum byte
	sum ^= h.Magic[0] ^ h.Magic[1] ^ h.Magic[2] ^ h.Magic[3]
	sum ^= byte(h.Type)
	sum ^= h.Version
	sum ^= byte(h.SwitchInterval >> 24)
	sum ^= byte(h.SwitchInterval >> 16)
	sum ^= byte(h.SwitchInterval >> 8)
	sum ^= byte(h.SwitchInterval)
	sum ^= h.ModesCount
	for _, mode := range h.Modes {
		sum ^= byte(mode)
	}
	sum ^= byte(h.CurrentMode >> 24)
	sum ^= byte(h.CurrentMode >> 16)
	sum ^= byte(h.CurrentMode >> 8)
	sum ^= byte(h.CurrentMode)
	for _, b := range h.Nonce {
		sum ^= b
	}
	sum ^= byte(h.Sequence >> 56)
	sum ^= byte(h.Sequence >> 48)
	sum ^= byte(h.Sequence >> 40)
	sum ^= byte(h.Sequence >> 32)
	sum ^= byte(h.Sequence >> 24)
	sum ^= byte(h.Sequence >> 16)
	sum ^= byte(h.Sequence >> 8)
	sum ^= byte(h.Sequence)
	sum ^= byte(h.Timestamp >> 56)
	sum ^= byte(h.Timestamp >> 48)
	sum ^= byte(h.Timestamp >> 40)
	sum ^= byte(h.Timestamp >> 32)
	sum ^= byte(h.Timestamp >> 24)
	sum ^= byte(h.Timestamp >> 16)
	sum ^= byte(h.Timestamp >> 8)
	sum ^= byte(h.Timestamp)
	return sum
}

func (h *Handshake) Verify() bool {
	if h.Magic[0] != 0xDE || h.Magic[1] != 0xAD || h.Magic[2] != 0xBE || h.Magic[3] != 0xEF {
		return false
	}
	if h.Version != 1 {
		return false
	}
	if h.Checksum != h.calcChecksum() {
		return false
	}
	return true
}

func (h *Handshake) Encode() []byte {
	modesLen := len(h.Modes) * 4
	buf := make([]byte, 4+1+1+4+1+modesLen+4+8+16+8+1)
	offset := 0

	copy(buf[offset:offset+4], h.Magic[:])
	offset += 4

	buf[offset] = byte(h.Type)
	offset++

	buf[offset] = h.Version
	offset++

	binary.BigEndian.PutUint32(buf[offset:offset+4], h.SwitchInterval)
	offset += 4

	buf[offset] = h.ModesCount
	offset++

	for _, mode := range h.Modes {
		binary.BigEndian.PutUint32(buf[offset:offset+4], uint32(mode))
		offset += 4
	}

	binary.BigEndian.PutUint32(buf[offset:offset+4], h.CurrentMode)
	offset += 4

	binary.BigEndian.PutUint64(buf[offset:offset+8], h.Timestamp)
	offset += 8

	copy(buf[offset:offset+16], h.Nonce[:])
	offset += 16

	binary.BigEndian.PutUint64(buf[offset:offset+8], h.Sequence)
	offset += 8

	buf[offset] = h.Checksum
	return buf
}

func DecodeHandshake(data []byte) (*Handshake, error) {
	if len(data) < 4+1+1+4+1 {
		return nil, ErrInvalidHandshakeMagic
	}

	h := &Handshake{}
	offset := 0

	copy(h.Magic[:], data[offset:offset+4])
	offset += 4

	h.Type = HandshakeType(data[offset])
	offset++

	h.Version = data[offset]
	offset++

	h.SwitchInterval = binary.BigEndian.Uint32(data[offset : offset+4])
	offset += 4

	h.ModesCount = data[offset]
	offset++

	if len(data) < offset+int(h.ModesCount)*4 {
		return nil, ErrInvalidHandshakeMagic
	}

	h.Modes = make([]ProtocolMode, h.ModesCount)
	for i := byte(0); i < h.ModesCount; i++ {
		mode := binary.BigEndian.Uint32(data[offset : offset+4])
		h.Modes[i] = ProtocolMode(mode)
		offset += 4
	}

	if len(data) < offset+4+8+16+8+1 {
		return nil, ErrInvalidHandshakeMagic
	}

	h.CurrentMode = binary.BigEndian.Uint32(data[offset : offset+4])
	offset += 4

	h.Timestamp = binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8

	copy(h.Nonce[:], data[offset:offset+16])
	offset += 16

	h.Sequence = binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8

	h.Checksum = data[offset]

	if !h.Verify() {
		return nil, ErrHandshakeChecksumMismatch
	}

	return h, nil
}

type HandshakeState struct {
	Sequence uint64
	LastSeen map[uint64]time.Time
	mu       sync.RWMutex
}

func NewHandshakeState() *HandshakeState {
	return &HandshakeState{
		Sequence: 0,
		LastSeen: make(map[uint64]time.Time),
		mu:       sync.RWMutex{},
	}
}

func (hs *HandshakeState) NextSequence() uint64 {
	hs.mu.Lock()
	defer hs.mu.Unlock()
	hs.Sequence++
	return hs.Sequence
}

func (hs *HandshakeState) IsReplay(sequence uint64, windowSize time.Duration) bool {
	hs.mu.RLock()
	defer hs.mu.RUnlock()

	lastTime, exists := hs.LastSeen[sequence]
	if !exists {
		return false
	}

	return time.Since(lastTime) < windowSize
}

func (hs *HandshakeState) MarkSeen(sequence uint64) {
	hs.mu.Lock()
	defer hs.mu.Unlock()

	hs.LastSeen[sequence] = time.Now()

	for seq, t := range hs.LastSeen {
		if time.Since(t) > time.Minute {
			delete(hs.LastSeen, seq)
		}
	}
}

type HandshakeManager struct {
	state   *HandshakeState
	authKey []byte
	timeout time.Duration
}

func NewHandshakeManager(authKey []byte, timeout time.Duration) *HandshakeManager {
	log.Printf("[Handshake] NewHandshakeManager: authKey length = %d", len(authKey))
	if len(authKey) > 0 {
		log.Printf("[Handshake] NewHandshakeManager: authKey first 5 bytes = %x", authKey[:5])
	}

	return &HandshakeManager{
		state:   NewHandshakeState(),
		authKey: authKey,
		timeout: timeout,
	}
}

func (hm *HandshakeManager) PerformClientHandshakeAsync(conn net.Conn, interval time.Duration, modes []ProtocolMode, currentMode ProtocolMode, readChan <-chan []byte, errChan chan error, timeout time.Duration) error {
	log.Printf("[Handshake] ========== CLIENT HANDSHAKE ASYNC START ==========")
	log.Printf("[Handshake] Connection: local=%s, remote=%s", conn.LocalAddr(), conn.RemoteAddr())
	log.Printf("[Handshake] Interval: %v, Modes: %v, CurrentMode: %v", interval, modes, currentMode)

	seq := hm.state.NextSequence()
	log.Printf("[Handshake] Using sequence: %d", seq)

	syn := NewHandshake(HandshakeSyn, interval, modes, currentMode, seq)
	synData := syn.Encode()
	log.Printf("[Handshake] SynData length: %d", len(synData))

	signature := hm.sign(synData)
	log.Printf("[Handshake] Signature length: %d", len(signature))

	packet := append(synData, signature...)
	log.Printf("[Handshake] Total packet length: %d", len(packet))

	log.Printf("[Handshake] Sending SYN to server (with retries)...")
	for i := 0; i < 3; i++ {
		if _, err := conn.Write(packet); err != nil {
			log.Printf("[Handshake] Write error (attempt %d): %v", i+1, err)
		} else {
			log.Printf("[Handshake] Wrote %d bytes (attempt %d)", len(packet), i+1)
		}
		time.Sleep(200 * time.Millisecond)
	}

	log.Printf("[Handshake] Waiting for ACK via channel (timeout: %v)", timeout)

	select {
	case ackData := <-readChan:
		log.Printf("[Handshake] Received %d bytes from channel", len(ackData))

		if len(ackData) < 32 {
			log.Printf("[Handshake] Response too short: %d bytes", len(ackData))
			return ErrAuthFailed
		}

		ackPayload := ackData[:len(ackData)-32]
		ackSignature := ackData[len(ackData)-32:]

		if !hm.verify(ackPayload, ackSignature) {
			log.Printf("[Handshake] ACK signature verification failed")
			return ErrAuthFailed
		}
		log.Printf("[Handshake] ACK signature verified")

		ack, err := DecodeHandshake(ackPayload)
		if err != nil {
			log.Printf("[Handshake] Decode error: %v", err)
			return err
		}
		log.Printf("[Handshake] ACK decoded: Type=%d, Sequence=%d", ack.Type, ack.Sequence)

		if ack.Type != HandshakeAck {
			log.Printf("[Handshake] Wrong response type: %d, expected %d", ack.Type, HandshakeAck)
			return ErrAuthFailed
		}

		if hm.state.IsReplay(ack.Sequence, 30*time.Second) {
			log.Printf("[Handshake] Replay detected for sequence %d", ack.Sequence)
			return ErrHandshakeReplay
		}

		hm.state.MarkSeen(ack.Sequence)
		log.Printf("[Handshake] ========== CLIENT HANDSHAKE SUCCESS ==========")
		return nil

	case err := <-errChan:
		log.Printf("[Handshake] Error from channel: %v", err)
		return err

	case <-time.After(timeout):
		log.Printf("[Handshake] Timeout waiting for ACK")
		return ErrHandshakeTimeout
	}
}

func (hm *HandshakeManager) PerformClientHandshake(conn net.Conn, interval time.Duration, modes []ProtocolMode, currentMode ProtocolMode) error {
	log.Printf("[Handshake] ========== CLIENT HANDSHAKE START ==========")
	log.Printf("[Handshake] Connection: local=%s, remote=%s", conn.LocalAddr(), conn.RemoteAddr())
	log.Printf("[Handshake] Interval: %v, Modes: %v, CurrentMode: %v", interval, modes, currentMode)

	seq := hm.state.NextSequence()
	log.Printf("[Handshake] Using sequence: %d", seq)

	syn := NewHandshake(HandshakeSyn, interval, modes, currentMode, seq)
	synData := syn.Encode()
	log.Printf("[Handshake] SynData length: %d", len(synData))

	signature := hm.sign(synData)
	log.Printf("[Handshake] Signature length: %d", len(signature))

	packet := append(synData, signature...)
	log.Printf("[Handshake] Total packet length: %d", len(packet))

	for i := 0; i < 3; i++ {
		if _, err := conn.Write(packet); err != nil {
			log.Printf("[Handshake] Write error (attempt %d): %v", i+1, err)
		}
		time.Sleep(200 * time.Millisecond)
	}

	if err := conn.SetReadDeadline(time.Now().Add(hm.timeout)); err != nil {
		log.Printf("[Handshake] SetReadDeadline error: %v", err)
		return err
	}

	ackBuf := make([]byte, 4096)
	n, err := conn.Read(ackBuf)
	if err != nil {
		log.Printf("[Handshake] Read error: %v", err)
		return err
	}

	log.Printf("[Handshake] Received %d bytes", n)

	if n < 32 {
		return ErrAuthFailed
	}

	ackData := ackBuf[:n-32]
	ackSignature := ackBuf[n-32 : n]

	if !hm.verify(ackData, ackSignature) {
		return ErrAuthFailed
	}

	ack, err := DecodeHandshake(ackData)
	if err != nil {
		return err
	}

	if ack.Type != HandshakeAck {
		return ErrAuthFailed
	}

	if hm.state.IsReplay(ack.Sequence, 30*time.Second) {
		return ErrHandshakeReplay
	}

	hm.state.MarkSeen(ack.Sequence)
	log.Printf("[Handshake] ========== CLIENT HANDSHAKE SUCCESS ==========")

	return nil
}

func (hm *HandshakeManager) PerformServerHandshake(conn net.Conn) (*SessionConfig, error) {
	log.Printf("[Handshake] ========== SERVER HANDSHAKE START ==========")
	log.Printf("[Handshake] Connection: local=%s, remote=%s", conn.LocalAddr(), conn.RemoteAddr())

	buf := make([]byte, 4096)
	if err := conn.SetReadDeadline(time.Now().Add(hm.timeout)); err != nil {
		log.Printf("[Handshake] SetReadDeadline error: %v", err)
		return nil, err
	}

	log.Printf("[Handshake] Waiting for SYN from client...")
	n, err := conn.Read(buf)
	if err != nil {
		log.Printf("[Handshake] Read error: %v", err)
		return nil, err
	}

	log.Printf("[Handshake] Received %d bytes", n)
	log.Printf("[Handshake] First 20 bytes: %x", buf[:min(n, 20)])

	if n < 32 {
		log.Printf("[Handshake] Data too short: %d bytes", n)
		return nil, ErrAuthFailed
	}

	synData := buf[:n-32]
	signature := buf[n-32 : n]

	if !hm.verify(synData, signature) {
		log.Printf("[Handshake] SYN signature verification failed")
		return nil, ErrAuthFailed
	}
	log.Printf("[Handshake] SYN signature verified")

	syn, err := DecodeHandshake(synData)
	if err != nil {
		log.Printf("[Handshake] Decode error: %v", err)
		return nil, err
	}

	log.Printf("[Handshake] SYN decoded: Type=%d, Interval=%d, Modes=%v, CurrentMode=%d, Sequence=%d",
		syn.Type, syn.SwitchInterval, syn.Modes, syn.CurrentMode, syn.Sequence)

	if syn.Type != HandshakeSyn {
		log.Printf("[Handshake] Wrong handshake type: %d, expected %d", syn.Type, HandshakeSyn)
		return nil, ErrAuthFailed
	}

	if hm.state.IsReplay(syn.Sequence, 30*time.Second) {
		log.Printf("[Handshake] Replay detected for sequence %d", syn.Sequence)
		return nil, ErrHandshakeReplay
	}

	hm.state.MarkSeen(syn.Sequence)

	config := &SessionConfig{
		SwitchInterval:         time.Duration(syn.SwitchInterval) * time.Second,
		Modes:                  syn.Modes,
		CurrentMode:            ProtocolMode(syn.CurrentMode),
		EnableReplayProtection: true,
		ReplayWindowSize:       64,
	}

	seq := hm.state.NextSequence()
	ack := NewHandshake(HandshakeAck, config.SwitchInterval, config.Modes, config.CurrentMode, seq)
	ackData := ack.Encode()
	ackSignature := hm.sign(ackData)

	log.Printf("[Handshake] Sending ACK, sequence=%d, length=%d", seq, len(ackData)+len(ackSignature))

	if err := conn.SetWriteDeadline(time.Now().Add(hm.timeout)); err != nil {
		log.Printf("[Handshake] SetWriteDeadline error: %v", err)
		return nil, err
	}

	for i := 0; i < 3; i++ {
		if _, err := conn.Write(append(ackData, ackSignature...)); err != nil {
			log.Printf("[Handshake] Write error (attempt %d): %v", i+1, err)
		} else {
			log.Printf("[Handshake] Wrote %d bytes ACK (attempt %d)", len(ackData)+len(ackSignature), i+1)
		}
		time.Sleep(200 * time.Millisecond)
	}

	log.Printf("[Handshake] ========== SERVER HANDSHAKE SUCCESS ==========")
	return config, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func (hm *HandshakeManager) sign(data []byte) []byte {
	h := hmac.New(sha256.New, hm.authKey)
	h.Write(data)
	return h.Sum(nil)
}

func (hm *HandshakeManager) verify(data, signature []byte) bool {
	expected := hm.sign(data)
	return hmac.Equal(expected, signature)
}

type ReplayProtection struct {
	seen    map[uint64]bool
	window  []uint64
	maxSize int
	mu      sync.RWMutex
}

func NewReplayProtection(maxSize int) *ReplayProtection {
	return &ReplayProtection{
		seen:    make(map[uint64]bool),
		window:  make([]uint64, 0),
		maxSize: maxSize,
	}
}

func (rp *ReplayProtection) CheckAndAdd(sequence uint64) bool {
	rp.mu.Lock()
	defer rp.mu.Unlock()

	if rp.seen[sequence] {
		return true
	}

	rp.seen[sequence] = true
	rp.window = append(rp.window, sequence)

	if len(rp.window) > rp.maxSize {
		oldest := rp.window[0]
		delete(rp.seen, oldest)
		rp.window = rp.window[1:]
	}

	return false
}

func (rp *ReplayProtection) Reset() {
	rp.mu.Lock()
	defer rp.mu.Unlock()

	rp.seen = make(map[uint64]bool)
	rp.window = make([]uint64, 0)
}
