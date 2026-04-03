package shred

import "time"

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
