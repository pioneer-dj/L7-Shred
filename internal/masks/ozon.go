package masks

import (
	"crypto/rand"
	"encoding/binary"
	"time"
)

type OzonMask struct {
	sessionID uint64
	requestID uint32
	sequence  uint32
	timestamp uint32
}

func NewOzonMask() *OzonMask {
	m := &OzonMask{
		sessionID: 0,
		requestID: 0,
		sequence:  0,
		timestamp: uint32(time.Now().Unix()),
	}
	rand.Read([]byte{byte(m.sessionID)})
	rand.Read([]byte{byte(m.requestID)})
	return m
}

func (o *OzonMask) Wrap(payload []byte) []byte {
	o.sequence++
	o.timestamp = uint32(time.Now().Unix())

	header := make([]byte, 24)
	copy(header[0:8], []byte("OZONAPIv2"))
	binary.BigEndian.PutUint64(header[8:16], o.sessionID)
	binary.BigEndian.PutUint32(header[16:20], o.requestID)
	binary.BigEndian.PutUint32(header[20:24], o.sequence)

	return append(header, payload...)
}

func (o *OzonMask) Unwrap(data []byte) ([]byte, error) {
	if len(data) < 24 {
		return nil, ErrInvalidPacket
	}
	return data[24:], nil
}

func (o *OzonMask) ID() string { return "ozon" }
