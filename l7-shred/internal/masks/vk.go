package masks

import (
	"crypto/rand"
	"encoding/binary"
	"math"
)

type VKMask struct {
	streamID   uint32
	packetNum  uint32
	magicBytes [4]byte
}

func NewVKMask() *VKMask {
	m := &VKMask{
		streamID:  uint32(math.MaxUint32),
		packetNum: 0,
	}
	streamIDBytes := make([]byte, 4)
	rand.Read(streamIDBytes)
	m.streamID = binary.BigEndian.Uint32(streamIDBytes)

	rand.Read(m.magicBytes[:])
	return m
}

func (v *VKMask) Wrap(payload []byte) []byte {
	header := make([]byte, 16)

	copy(header[0:4], v.magicBytes[:])
	binary.BigEndian.PutUint32(header[4:8], v.streamID)
	binary.BigEndian.PutUint32(header[8:12], v.packetNum)
	binary.BigEndian.PutUint32(header[12:16], uint32(len(payload)))

	v.packetNum++
	return append(header, payload...)
}

func (v *VKMask) Unwrap(data []byte) ([]byte, error) {
	if len(data) < 16 {
		return nil, ErrInvalidPacket
	}
	return data[16:], nil
}

func (v *VKMask) ID() string { return "vk" }
