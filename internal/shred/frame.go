package shred

import (
	"encoding/binary"
	"io"
)

type Frame struct {
	AuthToken [32]byte
	EncLen    uint16
	Payload   []byte
	Padding   []byte
}

type FrameParser struct {
	sessionID uint64
}

func NewFrameParser(sessionID uint64) *FrameParser {
	return &FrameParser{sessionID: sessionID}
}

func (p *FrameParser) WriteFrame(w io.Writer, data []byte, padding []byte, authToken [32]byte) error {
	encLen := uint16(len(data))

	if err := binary.Write(w, binary.BigEndian, authToken); err != nil {
		return err
	}
	if err := binary.Write(w, binary.BigEndian, encLen); err != nil {
		return err
	}
	if _, err := w.Write(data); err != nil {
		return err
	}
	if _, err := w.Write(padding); err != nil {
		return err
	}
	return nil
}

func (p *FrameParser) ReadFrame(r io.Reader) (*Frame, error) {
	frame := &Frame{}

	if _, err := io.ReadFull(r, frame.AuthToken[:]); err != nil {
		return nil, err
	}

	if err := binary.Read(r, binary.BigEndian, &frame.EncLen); err != nil {
		return nil, err
	}

	frame.Payload = make([]byte, frame.EncLen)
	if _, err := io.ReadFull(r, frame.Payload); err != nil {
		return nil, err
	}

	remaining := 0
	if remaining > 0 {
		frame.Padding = make([]byte, remaining)
		if _, err := io.ReadFull(r, frame.Padding); err != nil {
			return nil, err
		}
	}

	return frame, nil
}
