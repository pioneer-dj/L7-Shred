package masks

import (
	"crypto/rand"
	"encoding/binary"
)

type QUICMask struct {
	destConnID []byte
	srcConnID  []byte
	packetNum  uint64
	version    uint32
}

func NewQUICMask() *QUICMask {
	destID := make([]byte, 8)
	srcID := make([]byte, 8)
	rand.Read(destID)
	rand.Read(srcID)

	return &QUICMask{
		destConnID: destID,
		srcConnID:  srcID,
		version:    1,
		packetNum:  0,
	}
}

func (q *QUICMask) Wrap(payload []byte) []byte {
	headerLen := 1 + 4 + 8 + 8
	buf := make([]byte, headerLen+len(payload))

	buf[0] = 0xC0 | 0x03

	binary.BigEndian.PutUint32(buf[1:5], q.version)
	copy(buf[5:13], q.destConnID)
	copy(buf[13:21], q.srcConnID)

	packetNumEncoded := q.packetNum
	for i := 0; i < 4; i++ {
		buf[21+i] = byte(packetNumEncoded >> (i * 8))
	}
	q.packetNum++

	copy(buf[25:], payload)

	return buf
}

func (q *QUICMask) Unwrap(data []byte) []byte {
	if len(data) < 21 {
		return data
	}
	return data[25:]
}
