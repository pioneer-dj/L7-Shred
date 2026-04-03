package shred

import (
	"io"
	"time"
)

type ShredEngine struct {
	fragmentor *Fragmentor
	jitter     *TemporalJitter
	shaper     *TrafficShaper
}

func NewShredEngine() *ShredEngine {
	return &ShredEngine{
		fragmentor: NewFragmentor(32, 288),
		jitter:     NewTemporalJitter(2*time.Millisecond, 1*time.Millisecond, 0.005),
		shaper:     NewTrafficShaper(500, 1500, 10*time.Millisecond),
	}
}

func (s *ShredEngine) Process(reader io.Reader, writer io.Writer) error {
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
				if _, err := writer.Write(fragment); err != nil {
					return err
				}

				s.jitter.Apply()

				if s.jitter.ShouldDrop() {
					s.jitter.SimulatePacketLoss()
				}
			}
		}
	}
}
