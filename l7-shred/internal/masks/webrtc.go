package masks

import (
	"crypto/rand"
	"encoding/binary"
	"time"
)

type RTPHeader struct {
	Version     uint8
	Padding     bool
	Extension   bool
	CSRCCount   uint8
	Marker      bool
	PayloadType uint8
	Sequence    uint16
	Timestamp   uint32
	SSRC        uint32
}

type WebRTCMask struct {
	ssrc        uint32
	sequence    uint16
	timestamp   uint32
	payloadType uint8
}

func NewWebRTCMask() *WebRTCMask {
	ssrcBytes := make([]byte, 4)
	rand.Read(ssrcBytes)
	ssrc := binary.BigEndian.Uint32(ssrcBytes)

	seqBytes := make([]byte, 2)
	rand.Read(seqBytes)
	sequence := binary.BigEndian.Uint16(seqBytes)

	return &WebRTCMask{
		ssrc:        ssrc,
		sequence:    sequence,
		timestamp:   uint32(time.Now().UnixNano() / 1e6),
		payloadType: 111,
	}
}

func (w *WebRTCMask) Wrap(payload []byte) []byte {
	hasExt := false
	hasMarker := false

	randByte := make([]byte, 1)
	rand.Read(randByte)
	if randByte[0]&1 == 1 {
		hasExt = true
	}
	if randByte[0]&2 == 2 {
		hasMarker = true
	}

	header := &RTPHeader{
		Version:     2,
		Padding:     false,
		Extension:   hasExt,
		CSRCCount:   0,
		Marker:      hasMarker,
		PayloadType: w.payloadType,
		Sequence:    w.sequence,
		Timestamp:   w.timestamp,
		SSRC:        w.ssrc,
	}

	var extData []byte
	if hasExt {
		extLen := 4 + int(randByte[0]%32)
		extData = make([]byte, extLen)
		binary.BigEndian.PutUint16(extData[0:2], 0xBEDE) // ID
		binary.BigEndian.PutUint16(extData[2:4], uint16(extLen-4))
		rand.Read(extData[4:])
	}

	w.sequence++
	w.timestamp += uint32(len(payload)) / 2

	return w.marshalHeader(header, extData, payload)
}

func (w *WebRTCMask) marshalHeader(h *RTPHeader, extData []byte, payload []byte) []byte {
	extLen := len(extData)
	headerLen := 12 + extLen
	buf := make([]byte, headerLen+len(payload))

	firstByte := (h.Version << 6) | (boolToByte(h.Padding) << 5) | (boolToByte(h.Extension) << 4) | h.CSRCCount
	secondByte := (boolToByte(h.Marker) << 7) | h.PayloadType

	buf[0] = firstByte
	buf[1] = secondByte
	binary.BigEndian.PutUint16(buf[2:4], h.Sequence)
	binary.BigEndian.PutUint32(buf[4:8], h.Timestamp)
	binary.BigEndian.PutUint32(buf[8:12], h.SSRC)

	if extLen > 0 {
		copy(buf[12:12+extLen], extData)
	}

	copy(buf[headerLen:], payload)

	return buf
}

func boolToByte(b bool) byte {
	if b {
		return 1
	}
	return 0
}

func (w *WebRTCMask) Unwrap(data []byte) ([]byte, error) {
	if len(data) < 12 {
		return nil, ErrInvalidPacket
	}

	hasExtension := (data[0]>>4)&1 == 1

	headerLen := 12
	if hasExtension {
		if len(data) < 14 {
			return nil, ErrInvalidPacket
		}
		extLen := int(binary.BigEndian.Uint16(data[12:14]))
		headerLen = 12 + 4 + extLen
	}

	if len(data) < headerLen {
		return nil, ErrInvalidPacket
	}

	return data[headerLen:], nil
}

func (w *WebRTCMask) ID() string { return "webrtc" }
