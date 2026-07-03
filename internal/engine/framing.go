package engine

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
)

const maxFrameSize = 65535

var errFrameTooLarge = errors.New("frame too large")

func isStreamConn(c net.Conn) bool {
	_, ok := c.(*net.TCPConn)
	return ok
}

func writeFrame(c net.Conn, data []byte) error {
	if isStreamConn(c) {
		if len(data) > maxFrameSize {
			return errFrameTooLarge
		}
		buf := make([]byte, 4+len(data))
		binary.BigEndian.PutUint32(buf[:4], uint32(len(data)))
		copy(buf[4:], data)
		_, err := c.Write(buf)
		return err
	}
	_, err := c.Write(data)
	return err
}

func readFrame(c net.Conn, scratch []byte) ([]byte, error) {
	if isStreamConn(c) {
		var hdr [4]byte
		if _, err := io.ReadFull(c, hdr[:]); err != nil {
			return nil, err
		}
		length := binary.BigEndian.Uint32(hdr[:])
		if length == 0 || length > maxFrameSize {
			return nil, errFrameTooLarge
		}
		buf := make([]byte, length)
		if _, err := io.ReadFull(c, buf); err != nil {
			return nil, err
		}
		return buf, nil
	}
	n, err := c.Read(scratch)
	if err != nil {
		return nil, err
	}
	out := make([]byte, n)
	copy(out, scratch[:n])
	return out, nil
}
