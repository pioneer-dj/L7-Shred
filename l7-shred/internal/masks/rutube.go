package masks

import (
	"crypto/rand"
	"encoding/binary"
)

type RuTubeMask struct {
	chunkID    uint32
	sessionID  uint64
	magicBytes [2]byte
	usePadding bool
}

func NewRuTubeMask() *RuTubeMask {
	var sessionID uint64
	binary.Read(rand.Reader, binary.BigEndian, &sessionID)

	m := &RuTubeMask{
		chunkID:    0,
		sessionID:  sessionID,
		usePadding: true,
	}

	rand.Read(m.magicBytes[:])

	return m
}

func (r *RuTubeMask) Wrap(payload []byte) []byte {
	paddingLen := 0
	if r.usePadding {
		paddingByte := make([]byte, 1)
		rand.Read(paddingByte)
		paddingLen = int(paddingByte[0] % 32)
	}

	headerLen := 24
	totalLen := headerLen + len(payload) + paddingLen
	header := make([]byte, totalLen)

	header[0] = r.magicBytes[0]
	header[1] = r.magicBytes[1]
	header[2] = 0x00 // version
	header[3] = 0x01

	binary.BigEndian.PutUint32(header[4:8], r.chunkID)
	binary.BigEndian.PutUint64(header[8:16], r.sessionID)
	binary.BigEndian.PutUint32(header[16:20], uint32(len(payload)))

	flags := uint16(0)
	if paddingLen > 0 {
		flags |= 0x0001
	}
	binary.BigEndian.PutUint16(header[20:22], flags)

	binary.BigEndian.PutUint16(header[22:24], uint16(paddingLen))

	copy(header[headerLen:headerLen+len(payload)], payload)

	if paddingLen > 0 {
		padding := make([]byte, paddingLen)
		rand.Read(padding)
		copy(header[headerLen+len(payload):], padding)
	}

	r.chunkID++
	return header
}

func (r *RuTubeMask) Unwrap(data []byte) ([]byte, error) {
	if len(data) < 24 {
		return nil, ErrInvalidPacket
	}

	payloadLen := binary.BigEndian.Uint32(data[16:20])

	flags := binary.BigEndian.Uint16(data[20:22])
	paddingLen := binary.BigEndian.Uint16(data[22:24])

	headerLen := 24
	totalPayloadLen := int(payloadLen) + int(paddingLen)

	if len(data) < headerLen+totalPayloadLen {
		return nil, ErrInvalidPacket
	}

	if flags&0x0001 != 0 && paddingLen > 0 {
		return data[headerLen : headerLen+int(payloadLen)], nil
	}

	return data[headerLen : headerLen+int(payloadLen)], nil
}

func (r *RuTubeMask) ID() string { return "rutube" }
