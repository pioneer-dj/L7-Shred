package masks

import (
	"crypto/rand"
	"encoding/binary"
	"time"
)

type ZoomMask struct {
	meetingID uint64
	userID    uint32
	timestamp uint32
	sequence  uint16
	encrypted bool
}

func NewZoomMask() *ZoomMask {
	return &ZoomMask{
		meetingID: uint64(time.Now().UnixNano()),
		userID:    uint32(time.Now().Unix()),
		timestamp: uint32(time.Now().Unix()),
		sequence:  0,
		encrypted: true,
	}
}

func (z *ZoomMask) Wrap(payload []byte) []byte {
	headerLen := 18
	if z.encrypted {
		headerLen += 4
	}

	buf := make([]byte, headerLen+len(payload))

	binary.BigEndian.PutUint64(buf[0:8], z.meetingID)
	binary.BigEndian.PutUint32(buf[8:12], z.userID)
	binary.BigEndian.PutUint32(buf[12:16], z.timestamp)
	binary.BigEndian.PutUint16(buf[16:18], z.sequence)

	if z.encrypted {
		encBlock := make([]byte, 4)
		rand.Read(encBlock)
		copy(buf[18:22], encBlock)
	}

	copy(buf[headerLen:], payload)

	z.sequence++
	z.timestamp = uint32(time.Now().Unix())

	return buf
}

func (z *ZoomMask) Unwrap(data []byte) ([]byte, error) {
	minLen := 18
	if z.encrypted {
		minLen = 22
	}

	if len(data) < minLen {
		return nil, ErrInvalidPacket
	}

	headerLen := 18
	if z.encrypted {
		headerLen = 22
	}

	return data[headerLen:], nil
}

func (z *ZoomMask) ID() string { return "zoom" }
