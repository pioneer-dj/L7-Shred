package proto

import (
	"encoding/binary"
	"errors"
)

const (
	FrameFlagData = 0x01
	FrameFlagAck  = 0x02
	FrameFlagPing = 0x03
)

const FrameHeaderSize = 32 + 8 + 8 + 1 + 1 + 2

type Frame struct {
	AuthToken [32]byte
	Seq       uint64
	Ack       uint64
	Flags     byte
	MaskID    byte
	EncLen    uint16
	Payload   []byte
	Padding   []byte
}

func (f *Frame) Encode() []byte {
	encLen := uint16(len(f.Payload) + len(f.Padding))
	buf := make([]byte, FrameHeaderSize+int(encLen))
	copy(buf[0:32], f.AuthToken[:])
	binary.BigEndian.PutUint64(buf[32:40], f.Seq)
	binary.BigEndian.PutUint64(buf[40:48], f.Ack)
	buf[48] = f.Flags
	buf[49] = f.MaskID
	binary.BigEndian.PutUint16(buf[50:52], encLen)
	copy(buf[52:], f.Payload)
	copy(buf[52+len(f.Payload):], f.Padding)
	return buf
}

func DecodeFrame(data []byte) (*Frame, error) {
	if len(data) < FrameHeaderSize {
		return nil, errors.New("frame too short")
	}
	encLen := binary.BigEndian.Uint16(data[50:52])
	if len(data) < FrameHeaderSize+int(encLen) {
		return nil, errors.New("frame too short for payload")
	}
	payload := data[52 : 52+int(encLen)]
	return &Frame{
		AuthToken: *(*[32]byte)(data[0:32]),
		Seq:       binary.BigEndian.Uint64(data[32:40]),
		Ack:       binary.BigEndian.Uint64(data[40:48]),
		Flags:     data[48],
		MaskID:    data[49],
		EncLen:    encLen,
		Payload:   payload,
		Padding:   payload[0:0],
	}, nil
}
