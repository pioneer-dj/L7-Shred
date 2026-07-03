package masks

import (
	"crypto/rand"
	"encoding/binary"
	"time"
)

type YandexMask struct {
	requestID  [16]byte
	magicBytes [8]byte
	sequence   uint32
}

func NewYandexMask() *YandexMask {
	m := &YandexMask{
		sequence: 0,
	}
	rand.Read(m.requestID[:])
	rand.Read(m.magicBytes[:])
	return m
}

func (y *YandexMask) Wrap(payload []byte) []byte {
	y.sequence++

	headerLen := 38
	header := make([]byte, headerLen)

	copy(header[0:8], y.magicBytes[:])
	header[8] = 0x01
	header[9] = 0x00
	binary.BigEndian.PutUint32(header[10:14], y.sequence)
	timestamp := uint64(time.Now().Unix())
	binary.BigEndian.PutUint64(header[14:22], timestamp)
	copy(header[22:38], y.requestID[:])

	result := make([]byte, headerLen+len(payload))
	copy(result, header)
	copy(result[headerLen:], payload)

	return result
}

func (y *YandexMask) Unwrap(data []byte) ([]byte, error) {
	if len(data) < 38 {
		return nil, ErrInvalidPacket
	}
	return data[38:], nil
}

func (y *YandexMask) ID() string { return "yandex" }