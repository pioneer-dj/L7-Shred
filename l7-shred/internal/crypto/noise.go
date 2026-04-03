package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"io"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

type NoiseHandshake struct {
	initiator        bool
	staticPublic     [32]byte
	staticPrivate    [32]byte
	ephemeralPublic  [32]byte
	ephemeralPrivate [32]byte
	peerStatic       [32]byte
	peerEphemeral    [32]byte
	handshakeHash    []byte
	ck               []byte // chaining key
	h                []byte // handshake hash
	cipherKey        []byte
	finished         bool
}

func NewNoiseHandshake(initiator bool, staticPrivate []byte) (*NoiseHandshake, error) {
	n := &NoiseHandshake{
		initiator: initiator,
	}

	// Установка статического ключа
	if len(staticPrivate) == 32 {
		copy(n.staticPrivate[:], staticPrivate)
		curve25519.ScalarBaseMult(&n.staticPublic, &n.staticPrivate)
	} else {
		// Генерация новой пары
		if _, err := rand.Read(n.staticPrivate[:]); err != nil {
			return nil, err
		}
		curve25519.ScalarBaseMult(&n.staticPublic, &n.staticPrivate)
	}

	// Генерация эфемерной пары
	if _, err := rand.Read(n.ephemeralPrivate[:]); err != nil {
		return nil, err
	}
	curve25519.ScalarBaseMult(&n.ephemeralPublic, &n.ephemeralPrivate)

	// Инициализация хэша
	protocolName := []byte("Noise_XX_25519_ChaChaPoly_SHA256")
	hash := sha256.Sum256(protocolName)
	n.h = hash[:]
	n.ck = hash[:]

	return n, nil
}

func (n *NoiseHandshake) Handshake(conn io.ReadWriter) ([]byte, error) {
	if n.initiator {
		// -> e
		if err := n.writeMessage(conn, n.ephemeralPublic[:]); err != nil {
			return nil, err
		}
		n.mixHash(n.ephemeralPublic[:])

		// <- e, ee, s, es
		peerEphemeral, err := n.readMessage(conn, 32)
		if err != nil {
			return nil, err
		}
		copy(n.peerEphemeral[:], peerEphemeral)
		n.mixHash(n.peerEphemeral[:])

		// ee
		var shared [32]byte
		curve25519.ScalarMult(&shared, &n.ephemeralPrivate, &n.peerEphemeral)
		n.mixKey(shared[:])

		// peer static
		peerStatic, err := n.readMessage(conn, 32)
		if err != nil {
			return nil, err
		}
		copy(n.peerStatic[:], peerStatic)
		n.mixHash(n.peerStatic[:])

		// es
		curve25519.ScalarMult(&shared, &n.ephemeralPrivate, &n.peerStatic)
		n.mixKey(shared[:])

		// -> s, se
		if err := n.writeMessage(conn, n.staticPublic[:]); err != nil {
			return nil, err
		}
		n.mixHash(n.staticPublic[:])

		curve25519.ScalarMult(&shared, &n.staticPrivate, &n.peerEphemeral)
		n.mixKey(shared[:])

	} else {
		// <- e
		peerEphemeral, err := n.readMessage(conn, 32)
		if err != nil {
			return nil, err
		}
		copy(n.peerEphemeral[:], peerEphemeral)
		n.mixHash(n.peerEphemeral[:])

		// -> e, ee
		if err := n.writeMessage(conn, n.ephemeralPublic[:]); err != nil {
			return nil, err
		}
		n.mixHash(n.ephemeralPublic[:])

		var shared [32]byte
		curve25519.ScalarMult(&shared, &n.ephemeralPrivate, &n.peerEphemeral)
		n.mixKey(shared[:])

		// -> s, es
		if err := n.writeMessage(conn, n.staticPublic[:]); err != nil {
			return nil, err
		}
		n.mixHash(n.staticPublic[:])

		curve25519.ScalarMult(&shared, &n.staticPrivate, &n.peerEphemeral)
		n.mixKey(shared[:])

		// <- s, ee
		peerStatic, err := n.readMessage(conn, 32)
		if err != nil {
			return nil, err
		}
		copy(n.peerStatic[:], peerStatic)
		n.mixHash(n.peerStatic[:])

		curve25519.ScalarMult(&shared, &n.ephemeralPrivate, &n.peerStatic)
		n.mixKey(shared[:])
	}

	n.finished = true
	n.cipherKey = n.ck

	return n.cipherKey, nil
}

func (n *NoiseHandshake) writeMessage(conn io.Writer, data []byte) error {
	_, err := conn.Write(data)
	return err
}

func (n *NoiseHandshake) readMessage(conn io.Reader, size int) ([]byte, error) {
	buf := make([]byte, size)
	_, err := io.ReadFull(conn, buf)
	return buf, err
}

func (n *NoiseHandshake) mixHash(data []byte) {
	hash := sha256.Sum256(append(n.h, data...))
	n.h = hash[:]
}

func (n *NoiseHandshake) mixKey(data []byte) {
	kdf := hkdf.New(sha256.New, data, n.ck, nil)
	newCK := make([]byte, 32)
	kdf.Read(newCK)
	kdf.Read(n.ck) // temp
	n.ck = newCK
}

func (n *NoiseHandshake) GetPeerKey() []byte {
	return n.peerStatic[:]
}

func (n *NoiseHandshake) SetPeerKey(key []byte) {
	if len(key) == 32 {
		copy(n.peerStatic[:], key)
	}
}

func (n *NoiseHandshake) GetSharedSecret() []byte {
	return n.cipherKey
}

func (n *NoiseHandshake) SetSharedSecret(secret []byte) {
	n.cipherKey = secret
}

func (n *NoiseHandshake) GetCipherKey() []byte {
	return n.cipherKey
}
