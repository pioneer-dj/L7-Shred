package engine

import (
	"io"
	"time"

	"github.com/l7-shred/core/internal/crypto"
	"github.com/l7-shred/core/internal/shred"
)

type Shredder struct {
	fragmentor *shred.Fragmentor
	jitter     *shred.TemporalJitter
	shaper     *shred.TrafficShaper
	cipher     *crypto.AEADCipher
	sessionID  uint64
}

type Fragmentor struct {
	minSize      int
	maxSize      int
	currentSize  int
	lastRotation time.Time
}

func NewFragmentor(minSize, maxSize int) *Fragmentor {
	return &Fragmentor{
		minSize: minSize,
		maxSize: maxSize,
	}
}

func (f *Fragmentor) Fragment(data []byte) [][]byte {
	f.rotateIfNeeded()

	var fragments [][]byte
	remaining := data

	for len(remaining) > 0 {
		fragmentSize := f.currentSize
		if fragmentSize > len(remaining) {
			fragmentSize = len(remaining)
		}

		fragment := make([]byte, fragmentSize)
		copy(fragment, remaining[:fragmentSize])
		fragments = append(fragments, fragment)
		remaining = remaining[fragmentSize:]
	}

	return fragments
}

func (f *Fragmentor) rotateIfNeeded() {
	if time.Since(f.lastRotation) > 30*time.Second {
		f.currentSize = f.minSize + int(time.Now().UnixNano()%int64(f.maxSize-f.minSize))
		f.lastRotation = time.Now()
	}
}

func NewShredder(sessionID uint64, cipher *crypto.AEADCipher) *Shredder {
	return &Shredder{
		fragmentor: NewFragmentor(32, 288),
		jitter:     shred.NewTemporalJitter(2*time.Millisecond, 1*time.Millisecond, 0.005),
		shaper:     shred.NewTrafficShaper(500, 1500, 10*time.Millisecond),
		cipher:     cipher,
		sessionID:  sessionID,
	}
}

func (s *Shredder) Shred(reader io.Reader, writer io.Writer) error {
	buf := make([]byte, 65536)

	for {
		n, err := reader.Read(buf)
		if err != nil {
			return err
		}

		bursts := s.shaper.Process(buf[:n])

		for _, burst := range bursts {
			fragments := s.fragmentor.Fragment(burst)

			for _, fragment := range fragments {
				encrypted, err := s.cipher.Encrypt(fragment)
				if err != nil {
					return err
				}

				if _, err := writer.Write(encrypted); err != nil {
					return err
				}

				s.jitter.Apply()
			}
		}
	}
}
