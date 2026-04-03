package crypto

import (
	"crypto/sha256"
	"io"
)

type HybridKEX struct {
	kyber        *Kyber768
	noise        *NoiseHandshake
	sharedSecret []byte
}

func NewHybridKEX(initiator bool, staticPrivate []byte) (*HybridKEX, error) {
	kyber := NewKyber768()
	noise, err := NewNoiseHandshake(initiator, staticPrivate)
	if err != nil {
		return nil, err
	}

	return &HybridKEX{
		kyber: kyber,
		noise: noise,
	}, nil
}

func (h *HybridKEX) GenerateSharedSecret() ([]byte, []byte, error) {
	kyberPair, err := h.kyber.GenerateKeyPair()
	if err != nil {
		return nil, nil, err
	}

	ciphertext, kyberSecret, err := h.kyber.Encapsulate(kyberPair.Public)
	if err != nil {
		return nil, nil, err
	}

	noiseSecret := h.noise.GetSharedSecret()
	if noiseSecret == nil {
		return nil, nil, err
	}

	combined := append(kyberSecret, noiseSecret...)
	hash := sha256.Sum256(combined)

	return hash[:], ciphertext, nil
}

func (h *HybridKEX) DecapsulateSharedSecret(publicKey, ciphertext []byte) ([]byte, error) {
	kyberSecret, err := h.kyber.Decapsulate(publicKey, ciphertext)
	if err != nil {
		return nil, err
	}

	noiseSecret := h.noise.GetSharedSecret()
	if noiseSecret == nil {
		return nil, err
	}

	combined := append(kyberSecret, noiseSecret...)
	hash := sha256.Sum256(combined)

	return hash[:], nil
}

func (h *HybridKEX) Handshake(conn io.ReadWriter) error {
	sharedSecret, err := h.noise.Handshake(conn)
	if err != nil {
		return err
	}
	h.noise.SetSharedSecret(sharedSecret)
	return nil
}
