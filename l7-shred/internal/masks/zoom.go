package masks

import (
	"encoding/binary"
	"time"
)

type ZoomMask struct {
	meetingID uint64
	userID    uint32
	timestamp uint32
	sequence  uint16
}

func NewZoomMask() *ZoomMask {
	return &ZoomMask{
		meetingID: uint64(time.Now().UnixNano()),
		userID:    uint32(time.Now().Unix()),
		timestamp: uint32(time.Now().Unix()),
		sequence:  0,
	}
}

func (z *ZoomMask) Wrap(payload []byte) []byte {
	buf := make([]byte, 18+len(payload))

	binary.BigEndian.PutUint64(buf[0:8], z.meetingID)
	binary.BigEndian.PutUint32(buf[8:12], z.userID)
	binary.BigEndian.PutUint32(buf[12:16], z.timestamp)
	binary.BigEndian.PutUint16(buf[16:18], z.sequence)

	copy(buf[18:], payload)

	z.sequence++
	z.timestamp = uint32(time.Now().Unix())

	return buf
}
