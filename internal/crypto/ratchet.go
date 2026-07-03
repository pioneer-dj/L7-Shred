package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"hash"
)

type DoubleRatchet struct {
	rootKey      []byte
	chainKey     []byte
	sendChainKey []byte
	recvChainKey []byte
	sendN        uint32
	recvN        uint32
	mac          hash.Hash
}

func NewDoubleRatchet(rootKey []byte) *DoubleRatchet {
	return &DoubleRatchet{
		rootKey:  rootKey,
		chainKey: rootKey,
		sendN:    0,
		recvN:    0,
		mac:      hmac.New(sha256.New, rootKey),
	}
}

func (d *DoubleRatchet) RatchetSend() []byte {
	d.sendChainKey = d.kdf(d.chainKey, []byte{0x01})
	d.sendN++
	return d.kdf(d.sendChainKey, []byte{0x02})
}

func (d *DoubleRatchet) RatchetRecv() []byte {
	d.recvChainKey = d.kdf(d.chainKey, []byte{0x01})
	d.recvN++
	return d.kdf(d.recvChainKey, []byte{0x02})
}

func (d *DoubleRatchet) kdf(key, data []byte) []byte {
	d.mac.Reset()
	d.mac.Write(key)
	d.mac.Write(data)
	return d.mac.Sum(nil)
}

func (d *DoubleRatchet) Encrypt(plaintext []byte) ([]byte, []byte) {
	msgKey := d.kdf(d.sendChainKey, []byte{0x02})
	cipher, _ := NewAEADCipher(msgKey)
	encrypted, _ := cipher.Encrypt(plaintext)
	return encrypted, d.RatchetSend()
}

func (d *DoubleRatchet) Decrypt(ciphertext []byte) ([]byte, error) {
	msgKey := d.kdf(d.recvChainKey, []byte{0x02})
	cipher, _ := NewAEADCipher(msgKey)
	d.RatchetRecv()
	return cipher.Decrypt(ciphertext)
}
