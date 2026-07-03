package masks

import (
	"crypto/rand"
	"encoding/binary"
	"time"
)

type TeamsMask struct {
	conferenceID  uint64
	participantID uint32
	sequence      uint32
	encryptionKey [16]byte
}

func NewTeamsMask() *TeamsMask {
	key := [16]byte{}
	rand.Read(key[:])

	return &TeamsMask{
		conferenceID:  uint64(time.Now().UnixNano()),
		participantID: uint32(time.Now().Unix()),
		sequence:      0,
		encryptionKey: key,
	}
}

func (t *TeamsMask) Wrap(payload []byte) []byte {
	encryptedHeader := make([]byte, 8)
	rand.Read(encryptedHeader)

	headerLen := 20 + 8
	buf := make([]byte, headerLen+len(payload))

	binary.BigEndian.PutUint64(buf[0:8], t.conferenceID)
	binary.BigEndian.PutUint32(buf[8:12], t.participantID)
	binary.BigEndian.PutUint32(buf[12:16], t.sequence)
	binary.BigEndian.PutUint32(buf[16:20], uint32(len(payload)))

	copy(buf[20:28], encryptedHeader)

	copy(buf[28:], payload)

	paddingLen := 0
	if len(payload) < 1400 {
		paddingByte := make([]byte, 1)
		rand.Read(paddingByte)
		paddingLen = int(paddingByte[0] % 64)
		padding := make([]byte, paddingLen)
		rand.Read(padding)
		buf = append(buf, padding...)
	}

	t.sequence++
	return buf
}

func (t *TeamsMask) Unwrap(data []byte) ([]byte, error) {
	if len(data) < 28 {
		return nil, ErrInvalidPacket
	}

	payloadLen := binary.BigEndian.Uint32(data[16:20])

	headerLen := 28

	if len(data) < headerLen+int(payloadLen) {
		return nil, ErrInvalidPacket
	}

	return data[headerLen : headerLen+int(payloadLen)], nil
}

func (t *TeamsMask) ID() string { return "teams" }
