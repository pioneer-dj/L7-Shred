package masks

import (
	"crypto/rand"
	"encoding/binary"
)

type WinUpdateMask struct {
	sessionID   uint64
	updateID    uint32
	packageSize uint32
}

func NewWinUpdateMask() *WinUpdateMask {
	var sessionID uint64
	var updateID uint32
	binary.Read(rand.Reader, binary.BigEndian, &sessionID)
	binary.Read(rand.Reader, binary.BigEndian, &updateID)

	return &WinUpdateMask{
		sessionID: sessionID,
		updateID:  updateID,
	}
}

func (w *WinUpdateMask) Wrap(payload []byte) []byte {
	headerLen := 8 + 4 + 4 + 2
	buf := make([]byte, headerLen+len(payload))

	binary.BigEndian.PutUint64(buf[0:8], w.sessionID)
	binary.BigEndian.PutUint32(buf[8:12], w.updateID)
	binary.BigEndian.PutUint32(buf[12:16], uint32(len(payload)))

	crc := w.calcCRC(payload)
	binary.BigEndian.PutUint16(buf[16:18], crc)

	copy(buf[18:], payload)

	return buf
}

func (w *WinUpdateMask) calcCRC(data []byte) uint16 {
	var crc uint16
	for _, b := range data {
		crc ^= uint16(b) << 8
		for i := 0; i < 8; i++ {
			if (crc & 0x8000) != 0 {
				crc = (crc << 1) ^ 0x1021
			} else {
				crc <<= 1
			}
		}
	}
	return crc
}
