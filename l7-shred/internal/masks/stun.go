package masks

import (
	"crypto/rand"
	"encoding/binary"
)

type STUNMask struct {
	transactionID [12]byte
	magicCookie   uint32
}

func NewSTUNMask() *STUNMask {
	mask := &STUNMask{
		magicCookie: 0x2112A442,
	}
	rand.Read(mask.transactionID[:])
	return mask
}

func (s *STUNMask) Wrap(payload []byte) []byte {
	msgLen := uint16(len(payload))
	buf := make([]byte, 20+len(payload))

	binary.BigEndian.PutUint16(buf[0:2], 0x0001)
	binary.BigEndian.PutUint16(buf[2:4], msgLen)
	binary.BigEndian.PutUint32(buf[4:8], s.magicCookie)
	copy(buf[8:20], s.transactionID[:])
	copy(buf[20:], payload)

	return buf
}
