//ШУТКА

package masks

import (
	"crypto/rand"
	"encoding/binary"
)

type MinecraftMask struct {
	magic     [16]byte
	guid      uint64
	packetSeq uint32
	isOffline bool
}

func NewMinecraftMask() *MinecraftMask {
	m := &MinecraftMask{
		guid:      0,
		packetSeq: 0,
		isOffline: true,
	}
	rand.Read(m.magic[:])
	copy(m.magic[:], []byte{0x00, 0xff, 0xff, 0x00, 0xfe, 0xfe, 0xfe, 0xfe,
		0xfd, 0xfd, 0xfd, 0xfd, 0x12, 0x34, 0x56, 0x78})
	return m
}

func (m *MinecraftMask) Wrap(payload []byte) []byte {
	var header []byte

	if m.isOffline {
		header = make([]byte, 25)
		binary.BigEndian.PutUint64(header[1:9], uint64(len(payload)))
		binary.BigEndian.PutUint64(header[9:17], m.guid)
		header[24] = 0x01
	} else {
		header = make([]byte, 4)
		binary.BigEndian.PutUint32(header[0:4], m.packetSeq)
		m.packetSeq++
	}

	return append(header, payload...)
}

func (m *MinecraftMask) Unwrap(data []byte) ([]byte, error) {
	if m.isOffline {
		if len(data) < 25 {
			return nil, ErrInvalidPacket
		}
		return data[25:], nil
	}

	if len(data) < 4 {
		return nil, ErrInvalidPacket
	}
	return data[4:], nil
}

func (m *MinecraftMask) ID() string { return "minecraft" }
