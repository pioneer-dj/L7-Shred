package masks

import (
	"encoding/binary"
	"math/rand"
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
	return &WebRTCMask{
		ssrc:        rand.Uint32(),
		sequence:    uint16(rand.Uint32()),
		timestamp:   uint32(time.Now().UnixNano() / 1e6),
		payloadType: 111,
	}
}

func (w *WebRTCMask) Wrap(payload []byte) []byte {
	header := &RTPHeader{
		Version:     2,
		Padding:     false,
		Extension:   false,
		CSRCCount:   0,
		Marker:      false,
		PayloadType: w.payloadType,
		Sequence:    w.sequence,
		Timestamp:   w.timestamp,
		SSRC:        w.ssrc,
	}

	w.sequence++
	w.timestamp += uint32(len(payload)) / 2

	return w.marshalHeader(header, payload)
}

func (w *WebRTCMask) marshalHeader(h *RTPHeader, payload []byte) []byte {
	buf := make([]byte, 12+len(payload))

	firstByte := (h.Version << 6) | (boolToByte(h.Padding) << 5) | (boolToByte(h.Extension) << 4) | h.CSRCCount
	secondByte := (boolToByte(h.Marker) << 7) | h.PayloadType

	buf[0] = firstByte
	buf[1] = secondByte
	binary.BigEndian.PutUint16(buf[2:4], h.Sequence)
	binary.BigEndian.PutUint32(buf[4:8], h.Timestamp)
	binary.BigEndian.PutUint32(buf[8:12], h.SSRC)
	copy(buf[12:], payload)

	return buf
}

func boolToByte(b bool) byte {
	if b {
		return 1
	}
	return 0
}
