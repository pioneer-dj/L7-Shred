package utils

import (
	"sync"
)

type BufferPool struct {
	pool    sync.Pool
	maxSize int
}

func NewBufferPool(size int) *BufferPool {
	return &BufferPool{
		maxSize: size,
		pool: sync.Pool{
			New: func() interface{} {
				return make([]byte, 0, size)
			},
		},
	}
}

func (p *BufferPool) Get() []byte {
	return p.pool.Get().([]byte)
}

func (p *BufferPool) Put(buf []byte) {
	if cap(buf) > p.maxSize {
		return
	}
	buf = buf[:0]
	p.pool.Put(buf)
}

type ConnPool struct {
	pool sync.Map
}

func NewConnPool() *ConnPool {
	return &ConnPool{}
}

func (c *ConnPool) Store(key string, value interface{}) {
	c.pool.Store(key, value)
}

func (c *ConnPool) Load(key string) (interface{}, bool) {
	return c.pool.Load(key)
}

func (c *ConnPool) Delete(key string) {
	c.pool.Delete(key)
}
