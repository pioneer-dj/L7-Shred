package engine

import (
	"io"
	"time"

	"github.com/l7-shred/core/internal/crypto"
	"github.com/l7-shred/core/internal/proto"
	"github.com/l7-shred/core/internal/shred"
)

type Fragmentor struct {
	minSize      int
	maxSize      int
	currentSize  int
	lastRotation time.Time
}

func NewFragmentor(minSize, maxSize int) *Fragmentor {
	return &Fragmentor{
		minSize:     minSize,
		maxSize:     maxSize,
		currentSize: minSize,
	}
}

func (f *Fragmentor) Fragment(data []byte) [][]byte {
	f.rotateIfNeeded()

	var fragments [][]byte
	remaining := data

	for len(remaining) > 0 {
		size := f.currentSize
		if size > len(remaining) {
			size = len(remaining)
		}

		fragment := make([]byte, size)
		copy(fragment, remaining[:size])
		fragments = append(fragments, fragment)
		remaining = remaining[size:]
	}

	return fragments
}

func (f *Fragmentor) rotateIfNeeded() {
	if time.Since(f.lastRotation) > 30*time.Second {
		f.currentSize = f.minSize + int(time.Now().UnixNano()%int64(f.maxSize-f.minSize))
		f.lastRotation = time.Now()
	}
}

type Shredder struct {
	fragmentor *proto.Fragmentor
	jitter     *shred.TemporalJitter
	shaper     *shred.TrafficShaper
	cipher     *crypto.AEADCipher
	sessionID  uint64
}

func NewShredder(sessionID uint64, cipher *crypto.AEADCipher) *Shredder {
	return &Shredder{
		fragmentor: proto.NewFragmentor(32, 288),
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

		var processErr error
		s.shaper.Process(buf[:n], func(burst *shred.PooledBuffer) {
			if processErr != nil {
				burst.Release()
				return
			}

			s.fragmentor.FragmentWithCallback(burst.Bytes(), func(fragment *proto.PoolBuffer) {
				if processErr != nil {
					fragment.Release()
					return
				}

				encrypted, err := s.cipher.Encrypt(fragment.Buf[:fragment.Len])
				if err != nil {
					processErr = err
					fragment.Release()
					return
				}

				if _, err := writer.Write(encrypted); err != nil {
					processErr = err
					fragment.Release()
					return
				}

				s.jitter.Apply()
				fragment.Release()
			})

			burst.Release()
		})

		if processErr != nil {
			return processErr
		}
	}
}
