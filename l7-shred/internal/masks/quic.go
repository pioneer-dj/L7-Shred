package masks

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
)

type QUICMask struct {
	destConnID      []byte
	srcConnID       []byte
	packetNum       uint64
	version         uint32
	packetNumCipher cipher.AEAD
	secret          []byte
}

func NewQUICMask() *QUICMask {
	destID := make([]byte, 8)
	srcID := make([]byte, 8)
	secret := make([]byte, 32)
	rand.Read(destID)
	rand.Read(srcID)
	rand.Read(secret)

	block, _ := aes.NewCipher(secret)
	aead, _ := cipher.NewGCM(block)

	return &QUICMask{
		destConnID:      destID,
		srcConnID:       srcID,
		version:         1,
		packetNum:       0,
		packetNumCipher: aead,
		secret:          secret,
	}
}

func (q *QUICMask) Wrap(payload []byte) []byte {
	headerLen := 1 + 4 + 8 + 8 + 16
	buf := make([]byte, headerLen+len(payload))

	buf[0] = 0xC0 | 0x03

	binary.BigEndian.PutUint32(buf[1:5], q.version)
	copy(buf[5:13], q.destConnID)
	copy(buf[13:21], q.srcConnID)

	nonce := make([]byte, 12)
	rand.Read(nonce)
	encryptedPN := q.packetNumCipher.Seal(nil, nonce,
		[]byte{byte(q.packetNum >> 56), byte(q.packetNum >> 48),
			byte(q.packetNum >> 40), byte(q.packetNum >> 32),
			byte(q.packetNum >> 24), byte(q.packetNum >> 16),
			byte(q.packetNum >> 8), byte(q.packetNum)}, nil)

	copy(buf[21:37], encryptedPN)
	copy(buf[37:], nonce)
	copy(buf[49:], payload)

	q.packetNum++
	return buf
}

func (q *QUICMask) Unwrap(data []byte) ([]byte, error) {
	if len(data) < 49 {
		return nil, ErrInvalidPacket
	}

	encryptedPN := data[21:37]
	nonce := data[37:49]

	decryptedPN, err := q.packetNumCipher.Open(nil, nonce, encryptedPN, nil)
	if err != nil {
		return nil, err
	}

	_ = decryptedPN

	return data[49:], nil
}

func (q *QUICMask) ID() string { return "quic" }
