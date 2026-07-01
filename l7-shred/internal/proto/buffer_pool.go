package proto

import "sync"

const PoolBufferSize = 2048

type PoolBuffer struct {
	Buf  []byte
	Len  int
	pool *sync.Pool
}

func (pb *PoolBuffer) Release() {
	if pb == nil {
		return
	}
	if pb.pool != nil && pb.Buf != nil {
		pb.pool.Put(pb)
	}
}

func NewBufferPool() *sync.Pool {
	return &sync.Pool{
		New: func() interface{} {
			buf := make([]byte, PoolBufferSize)
			return &PoolBuffer{Buf: buf, Len: 0, pool: nil}
		},
	}
}

var DefaultBufferPool = NewBufferPool()

func GetBuffer() *PoolBuffer {
	pb := DefaultBufferPool.Get().(*PoolBuffer)
	pb.pool = DefaultBufferPool
	pb.Len = 0
	return pb
}
