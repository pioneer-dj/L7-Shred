package masks

import (
	"crypto/rand"
	"encoding/binary"
)

type WildberriesMask struct {
	userID    uint64
	sessionID uint32
	packetNum uint32
}

func NewWildberriesMask() *WildberriesMask {
	m := &WildberriesMask{
		userID:    0,
		sessionID: 0,
		packetNum: 0,
	}
	rand.Read([]byte{byte(m.userID)})
	rand.Read([]byte{byte(m.sessionID)})
	return m
}

func (w *WildberriesMask) Wrap(payload []byte) []byte {
	w.packetNum++
	header := make([]byte, 20)
	copy(header[0:8], []byte("WBAPI2025"))
	binary.BigEndian.PutUint64(header[8:16], w.userID)
	binary.BigEndian.PutUint32(header[16:20], w.packetNum)
	return append(header, payload...)
}

func (w *WildberriesMask) Unwrap(data []byte) ([]byte, error) {
	if len(data) < 20 {
		return nil, ErrInvalidPacket
	}
	return data[20:], nil
}

func (w *WildberriesMask) ID() string { return "wildberries" }
