package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
)

type AEADCipher struct {
	aead  cipher.AEAD
	nonce []byte
}

func NewAEADCipher(key []byte) (*AEADCipher, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return &AEADCipher{
		aead:  aead,
		nonce: make([]byte, aead.NonceSize()),
	}, nil
}

func (c *AEADCipher) Encrypt(plaintext []byte) ([]byte, error) {
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	ciphertext := c.aead.Seal(nil, nonce, plaintext, nil)
	return append(nonce, ciphertext...), nil
}

func (c *AEADCipher) Decrypt(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < c.aead.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}

	nonce := ciphertext[:c.aead.NonceSize()]
	encrypted := ciphertext[c.aead.NonceSize():]

	return c.aead.Open(nil, nonce, encrypted, nil)
}
