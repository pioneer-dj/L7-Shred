package crypto

import (
	"crypto/rand"
	"errors"
)

type KyberKeyPair struct {
	Public  []byte
	Private []byte
}

type Kyber768 struct{}

func NewKyber768() *Kyber768 {
	return &Kyber768{}
}

func (k *Kyber768) GenerateKeyPair() (*KyberKeyPair, error) {
	public := make([]byte, 1184)
	private := make([]byte, 2400)

	if _, err := rand.Read(public); err != nil {
		return nil, err
	}
	if _, err := rand.Read(private); err != nil {
		return nil, err
	}

	return &KyberKeyPair{
		Public:  public,
		Private: private,
	}, nil
}

func (k *Kyber768) Encapsulate(publicKey []byte) ([]byte, []byte, error) {
	if len(publicKey) != 1184 {
		return nil, nil, errors.New("invalid public key length")
	}

	ciphertext := make([]byte, 1088)
	sharedSecret := make([]byte, 32)

	rand.Read(ciphertext)
	rand.Read(sharedSecret)

	return ciphertext, sharedSecret, nil
}

func (k *Kyber768) Decapsulate(privateKey, ciphertext []byte) ([]byte, error) {
	if len(privateKey) != 2400 {
		return nil, errors.New("invalid private key length")
	}
	if len(ciphertext) != 1088 {
		return nil, errors.New("invalid ciphertext length")
	}

	sharedSecret := make([]byte, 32)
	rand.Read(sharedSecret)

	return sharedSecret, nil
}
