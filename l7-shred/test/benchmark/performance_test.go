package benchmark

import (
	"testing"

	"github.com/l7-shred/core/internal/crypto"
)

func BenchmarkEncryption(b *testing.B) {
	cipher, _ := crypto.NewAEADCipher(make([]byte, 32))
	data := make([]byte, 1024)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cipher.Encrypt(data)
	}
}

func BenchmarkDecryption(b *testing.B) {
	cipher, _ := crypto.NewAEADCipher(make([]byte, 32))
	data := make([]byte, 1024)
	encrypted, _ := cipher.Encrypt(data)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cipher.Decrypt(encrypted)
	}
}

func BenchmarkNoiseHandshake(b *testing.B) {
	for i := 0; i < b.N; i++ {
		server, _ := crypto.NewNoiseHandshake(false, nil)
		client, _ := crypto.NewNoiseHandshake(true, nil)

		go server.Handshake(nil)
		client.Handshake(nil)
	}
}

func BenchmarkPaddingGeneration(b *testing.B) {
	engine := crypto.NewPaddingEngine(32, 288)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		engine.Generate()
	}
}

func BenchmarkRTPWrap(b *testing.B) {
	mask := NewWebRTCMask()
	data := make([]byte, 1400)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		mask.Wrap(data)
	}
}
