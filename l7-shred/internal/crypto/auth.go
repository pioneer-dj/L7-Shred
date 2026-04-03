package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"time"
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
