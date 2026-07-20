package masks

import (
	"crypto/rand"
	"encoding/binary"
)

type BrowserMask struct {
	sessionID uint64
	packetNum uint32
}

func NewBrowserMask() *BrowserMask {
	var sessionID uint64
	rand.Read([]byte{byte(sessionID)})
	binary.Read(rand.Reader, binary.BigEndian, &sessionID)

	return &BrowserMask{
		sessionID: sessionID,
		packetNum: 0,
	}
}

func (b *BrowserMask) Wrap(payload []byte) []byte {
	// Простой заголовок, который не ломает TLS
	// 8 байт sessionID + 4 байта packetNum + 2 байта длина
	header := make([]byte, 14)

	binary.BigEndian.PutUint64(header[0:8], b.sessionID)
	binary.BigEndian.PutUint32(header[8:12], b.packetNum)
	binary.BigEndian.PutUint16(header[12:14], uint16(len(payload)))

	b.packetNum++

	// Если это TLS пакет — добавляем минимальный заголовок
	// чтобы не сломать хэндшейк
	if len(payload) >= 5 && payload[0] == 0x16 && payload[1] == 0x03 {
		// TLS пакет — просто добавляем 14 байт заголовка
		return append(header, payload...)
	}

	// Не TLS — добавляем заголовок + паддинг
	paddingLen := 0
	if len(payload) < 1400 {
		paddingByte := make([]byte, 1)
		rand.Read(paddingByte)
		paddingLen = int(paddingByte[0] % 32)
	}

	result := make([]byte, len(header)+len(payload)+paddingLen)
	copy(result, header)
	copy(result[len(header):], payload)

	if paddingLen > 0 {
		padding := make([]byte, paddingLen)
		rand.Read(padding)
		copy(result[len(header)+len(payload):], padding)
	}

	return result
}

func (b *BrowserMask) Unwrap(data []byte) ([]byte, error) {
	if len(data) < 14 {
		return nil, ErrInvalidPacket
	}

	// Проверяем, является ли это TLS-пакетом (без заголовка)
	if len(data) >= 5 && data[0] == 0x16 && data[1] == 0x03 {
		return data, nil
	}

	payloadLen := int(binary.BigEndian.Uint16(data[12:14]))

	if len(data) < 14+payloadLen {
		return nil, ErrInvalidPacket
	}

	return data[14 : 14+payloadLen], nil
}

func (b *BrowserMask) ID() string { return "browser" }