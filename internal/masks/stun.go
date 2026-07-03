package masks

import (
	"crypto/rand"
	"encoding/binary"
)

type STUNMask struct {
	transactionID  [12]byte
	magicCookie    uint32
	useFingerprint bool
}

func NewSTUNMask() *STUNMask {
	mask := &STUNMask{
		magicCookie:    0x2112A442,
		useFingerprint: true,
	}
	rand.Read(mask.transactionID[:])
	return mask
}

func (s *STUNMask) Wrap(payload []byte) []byte {
	msgLen := uint16(len(payload))

	fingerprintLen := 0
	if s.useFingerprint {
		fingerprintLen = 4
	}

	buf := make([]byte, 20+len(payload)+fingerprintLen)

	binary.BigEndian.PutUint16(buf[0:2], 0x0001)
	binary.BigEndian.PutUint16(buf[2:4], msgLen)
	binary.BigEndian.PutUint32(buf[4:8], s.magicCookie)
	copy(buf[8:20], s.transactionID[:])

	copy(buf[20:20+len(payload)], payload)

	if s.useFingerprint {
		offset := 20 + len(payload)
		binary.BigEndian.PutUint16(buf[offset:offset+2], 0x8028)
		binary.BigEndian.PutUint16(buf[offset+2:offset+4], 4)
		crc := s.calcFingerprint(buf[:offset+4])
		binary.BigEndian.PutUint32(buf[offset+4:offset+8], crc)
	}

	return buf
}

func (s *STUNMask) Unwrap(data []byte) ([]byte, error) {
	if len(data) < 20 {
		return nil, ErrInvalidPacket
	}

	magicCookie := binary.BigEndian.Uint32(data[4:8])
	if magicCookie != s.magicCookie {
	}

	msgLen := binary.BigEndian.Uint16(data[2:4])

	hasFingerprint := false
	offset := 20 + int(msgLen)

	if len(data) >= offset+8 {
		attrType := binary.BigEndian.Uint16(data[offset : offset+2])
		if attrType == 0x8028 {
			hasFingerprint = true
		}
	}

	payloadLen := int(msgLen)
	if hasFingerprint {
		payloadLen -= 8
	}

	if len(data) < 20+payloadLen {
		return nil, ErrInvalidPacket
	}

	return data[20 : 20+payloadLen], nil
}

func (s *STUNMask) calcFingerprint(data []byte) uint32 {
	var crc uint32 = 0xFFFFFFFF
	for _, b := range data {
		crc ^= uint32(b) << 24
		for i := 0; i < 8; i++ {
			if crc&0x80000000 != 0 {
				crc = (crc << 1) ^ 0x04C11DB7
			} else {
				crc <<= 1
			}
		}
	}
	return crc ^ 0xFFFFFFFF
}

func (s *STUNMask) ID() string { return "stun" }
