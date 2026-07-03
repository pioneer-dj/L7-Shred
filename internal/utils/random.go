package utils

import (
	"crypto/rand"
	"encoding/binary"
	"math/big"
	"time"
)

func RandomBytes(n int) ([]byte, error) {
	buf := make([]byte, n)
	_, err := rand.Read(buf)
	return buf, err
}

func RandomInt(min, max int) int {
	if min == max {
		return min
	}

	diff := int64(max - min)
	n, _ := rand.Int(rand.Reader, big.NewInt(diff))
	return min + int(n.Int64())
}

func RandomUint64() uint64 {
	var n uint64
	binary.Read(rand.Reader, binary.BigEndian, &n)
	return n
}

func RandomDuration(min, max time.Duration) time.Duration {
	return min + time.Duration(RandomInt(int(min), int(max)))
}
