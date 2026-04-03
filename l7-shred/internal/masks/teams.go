package masks

import (
	"encoding/binary"
	"time"
)

type TeamsMask struct {
	conferenceID  uint64
	participantID uint32
	sequence      uint32
}

func NewTeamsMask() *TeamsMask {
	return &TeamsMask{
		conferenceID:  uint64(time.Now().UnixNano()),
		participantID: uint32(time.Now().Unix()),
		sequence:      0,
	}
}

func (t *TeamsMask) Wrap(payload []byte) []byte {
	buf := make([]byte, 20+len(payload))

	binary.BigEndian.PutUint64(buf[0:8], t.conferenceID)
	binary.BigEndian.PutUint32(buf[8:12], t.participantID)
	binary.BigEndian.PutUint32(buf[12:16], t.sequence)
	binary.BigEndian.PutUint32(buf[16:20], uint32(len(payload)))

	copy(buf[20:], payload)

	t.sequence++

	return buf
}
