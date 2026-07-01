package shred

import (
	"sync"
	"time"
)

const maxPooledBufferSize = 2048

var BytePool = sync.Pool{
	New: func() interface{} {
		buf := make([]byte, maxPooledBufferSize)
		return &buf
	},
}

type PooledBuffer struct {
	buf     []byte
	length  int
	pool    *sync.Pool
	ownedBy bool
}

func (pb *PooledBuffer) Bytes() []byte {
	if pb == nil {
		return nil
	}
	return pb.buf[:pb.length]
}

func (pb *PooledBuffer) Release() {
	if pb == nil {
		return
	}
	pb.length = 0
	if pb.pool != nil && pb.buf != nil {
		pb.pool.Put(&pb.buf)
	}
}

func GetPooledBuffer() *PooledBuffer {
	bufPtr := BytePool.Get().(*[]byte)
	return &PooledBuffer{buf: *bufPtr, pool: &BytePool, ownedBy: true}
}

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

func (f *Fragmentor) Fragment(data []byte, emit func(*PooledBuffer)) {
	f.FragmentWithCallback(data, emit)
}

func (f *Fragmentor) FragmentWithCallback(data []byte, emit func(*PooledBuffer)) {
	f.rotateIfNeeded()

	remaining := data
	for len(remaining) > 0 {
		size := f.currentSize
		if size > len(remaining) {
			size = len(remaining)
		}

		buffer := GetPooledBuffer()
		copy(buffer.buf[:size], remaining[:size])
		buffer.length = size
		emit(buffer)
		remaining = remaining[size:]
	}
}

func (f *Fragmentor) rotateIfNeeded() {
	if time.Since(f.lastRotation) > 30*time.Second {
		f.currentSize = f.minSize + int(time.Now().UnixNano()%int64(f.maxSize-f.minSize))
		f.lastRotation = time.Now()
	}
}
