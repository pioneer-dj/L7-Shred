package crypto

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"time"
)

var (
	ErrInvalidToken = errors.New("invalid authentication token")
	ErrExpiredToken = errors.New("token expired")
)

type TokenAuthenticator struct {
	secret     []byte
	windowSize int64
}

func NewTokenAuthenticator(secret []byte, windowSize int64) *TokenAuthenticator {
	return &TokenAuthenticator{
		secret:     secret,
		windowSize: windowSize,
	}
}

func (t *TokenAuthenticator) GenerateToken(sessionID uint64) [32]byte {
	timestamp := time.Now().Unix()

	data := make([]byte, 16)
	binary.BigEndian.PutUint64(data[0:8], sessionID)
	binary.BigEndian.PutUint64(data[8:16], uint64(timestamp))

	h := hmac.New(sha256.New, t.secret)
	h.Write(data)

	var token [32]byte
	copy(token[:], h.Sum(nil))

	return token
}

func (t *TokenAuthenticator) ValidateToken(token [32]byte, sessionID uint64) bool {
	now := time.Now().Unix()

	for offset := -t.windowSize; offset <= t.windowSize; offset++ {
		timestamp := now + offset

		data := make([]byte, 16)
		binary.BigEndian.PutUint64(data[0:8], sessionID)
		binary.BigEndian.PutUint64(data[8:16], uint64(timestamp))

		h := hmac.New(sha256.New, t.secret)
		h.Write(data)

		var expected [32]byte
		copy(expected[:], h.Sum(nil))

		if hmac.Equal(token[:], expected[:]) {
			return true
		}
	}

	return false
}

func (t *TokenAuthenticator) GenerateHandshakeAuth(sessionID uint64, nonce []byte) []byte {
	data := make([]byte, 8+len(nonce))
	binary.BigEndian.PutUint64(data[0:8], sessionID)
	copy(data[8:], nonce)

	h := hmac.New(sha256.New, t.secret)
	h.Write(data)
	return h.Sum(nil)
}

func (t *TokenAuthenticator) ValidateHandshakeAuth(sessionID uint64, nonce, signature []byte) bool {
	expected := t.GenerateHandshakeAuth(sessionID, nonce)
	return hmac.Equal(signature, expected)
}

func GenerateRandomSecret() []byte {
	secret := make([]byte, 32)
	rand.Read(secret)
	return secret
}

type SessionAuthenticator struct {
	sessions map[uint64]time.Time
}

func NewSessionAuthenticator() *SessionAuthenticator {
	return &SessionAuthenticator{
		sessions: make(map[uint64]time.Time),
	}
}

func (sa *SessionAuthenticator) RegisterSession(sessionID uint64, duration time.Duration) {
	sa.sessions[sessionID] = time.Now().Add(duration)
}

func (sa *SessionAuthenticator) IsSessionValid(sessionID uint64) bool {
	expiry, exists := sa.sessions[sessionID]
	if !exists {
		return false
	}
	return time.Now().Before(expiry)
}

func (sa *SessionAuthenticator) RevokeSession(sessionID uint64) {
	delete(sa.sessions, sessionID)
}

func (sa *SessionAuthenticator) Cleanup() {
	now := time.Now()
	for id, expiry := range sa.sessions {
		if now.After(expiry) {
			delete(sa.sessions, id)
		}
	}
}

type HandshakeAuthenticator struct {
	secret []byte
}

func NewHandshakeAuthenticator(secret []byte) *HandshakeAuthenticator {
	return &HandshakeAuthenticator{
		secret: secret,
	}
}

func (ha *HandshakeAuthenticator) Sign(data []byte) []byte {
	h := hmac.New(sha256.New, ha.secret)
	h.Write(data)
	return h.Sum(nil)
}

func (ha *HandshakeAuthenticator) Verify(data, signature []byte) bool {
	expected := ha.Sign(data)
	return hmac.Equal(signature, expected)
}
