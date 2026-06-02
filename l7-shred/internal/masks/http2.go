package masks

import (
	"crypto/rand"
	"encoding/binary"
)

type HTTP2Frame struct {
	Length   uint32
	Type     byte
	Flags    byte
	StreamID uint32
	Payload  []byte
}

const (
	FrameTypeData         byte = 0x00
	FrameTypeHeaders      byte = 0x01
	FrameTypePriority     byte = 0x02
	FrameTypeRSTStream    byte = 0x03
	FrameTypeSettings     byte = 0x04
	FrameTypePushPromise  byte = 0x05
	FrameTypePing         byte = 0x06
	FrameTypeGoAway       byte = 0x07
	FrameTypeWindowUpdate byte = 0x08
	FrameTypeContinuation byte = 0x09
)

func putUint24(b []byte, v uint32) {
	b[0] = byte(v >> 16)
	b[1] = byte(v >> 8)
	b[2] = byte(v)
}

func NewHTTP2SettingsFrame() []byte {
	payload := make([]byte, 12)
	binary.BigEndian.PutUint16(payload[0:2], 0x0004)
	binary.BigEndian.PutUint32(payload[2:6], 65535)
	binary.BigEndian.PutUint16(payload[6:8], 0x0006)
	binary.BigEndian.PutUint32(payload[8:12], 16384)

	frame := make([]byte, 9+len(payload))
	putUint24(frame[0:3], uint32(len(payload)))
	frame[3] = FrameTypeSettings
	frame[4] = 0x00
	binary.BigEndian.PutUint32(frame[5:9], 0)
	copy(frame[9:], payload)
	return frame
}

func NewHTTP2WindowUpdateFrame(streamID, increment uint32) []byte {
	payload := make([]byte, 4)
	binary.BigEndian.PutUint32(payload, increment)

	frame := make([]byte, 9+len(payload))
	putUint24(frame[0:3], 4)
	frame[3] = FrameTypeWindowUpdate
	frame[4] = 0x00
	binary.BigEndian.PutUint32(frame[5:9], streamID)
	copy(frame[9:], payload)
	return frame
}

func NewHTTP2PingFrame() []byte {
	payload := make([]byte, 8)
	rand.Read(payload)

	frame := make([]byte, 9+len(payload))
	putUint24(frame[0:3], 8)
	frame[3] = FrameTypePing
	frame[4] = 0x00
	binary.BigEndian.PutUint32(frame[5:9], 0)
	copy(frame[9:], payload)
	return frame
}

func NewHTTP2HeadersFrame(streamID uint32, headers []byte, endStream bool) []byte {
	flags := byte(0x04)
	if endStream {
		flags |= 0x01
	}

	frame := make([]byte, 9+len(headers))
	putUint24(frame[0:3], uint32(len(headers)))
	frame[3] = FrameTypeHeaders
	frame[4] = flags
	binary.BigEndian.PutUint32(frame[5:9], streamID)
	copy(frame[9:], headers)
	return frame
}

func NewHTTP2DataFrame(streamID uint32, data []byte, endStream bool) []byte {
	flags := byte(0x00)
	if endStream {
		flags |= 0x01
	}

	frame := make([]byte, 9+len(data))
	putUint24(frame[0:3], uint32(len(data)))
	frame[3] = FrameTypeData
	frame[4] = flags
	binary.BigEndian.PutUint32(frame[5:9], streamID)
	copy(frame[9:], data)
	return frame
}

func NewHTTP2GoAwayFrame(lastStreamID uint32, errorCode uint32) []byte {
	payload := make([]byte, 8)
	binary.BigEndian.PutUint32(payload[0:4], lastStreamID)
	binary.BigEndian.PutUint32(payload[4:8], errorCode)

	frame := make([]byte, 9+len(payload))
	putUint24(frame[0:3], 8)
	frame[3] = FrameTypeGoAway
	frame[4] = 0x00
	binary.BigEndian.PutUint32(frame[5:9], 0)
	copy(frame[9:], payload)
	return frame
}

func GenerateHTTP2Preface() []byte {
	return []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
}
