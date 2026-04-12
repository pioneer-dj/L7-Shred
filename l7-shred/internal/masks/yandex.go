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
	headerLen := 32 + 4 // +4 для sequence
	header := make([]byte, headerLen)

	copy(header[0:8], y.magicBytes[:])
	header[8] = 0x01 // version major
	header[9] = 0x00 // version minor

	binary.BigEndian.PutUint32(header[10:14], y.sequence)
	y.sequence++

	timestamp := uint64(time.Now().Unix())
	binary.BigEndian.PutUint64(header[14:22], timestamp)

	copy(header[22:38], y.requestID[:])

	paddingLen := 0
	paddingByte := make([]byte, 1)
	rand.Read(paddingByte)
	paddingLen = int(paddingByte[0] % 16)

	if paddingLen > 0 {
		padding := make([]byte, paddingLen)
		rand.Read(padding)
		header = append(header, padding...)
	}

	return append(header, payload...)
}

func (y *YandexMask) Unwrap(data []byte) ([]byte, error) {
	minLen := 38
	if len(data) < minLen {
		return nil, ErrInvalidPacket
	}

	if data[8] != 0x01 {
	}

	headerLen := 38

	if len(data) < headerLen {
		return nil, ErrInvalidPacket
	}

	return data[headerLen:], nil
}

func (y *YandexMask) ID() string { return "yandex" }
