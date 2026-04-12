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
	ssrc          uint32
	sequence      uint16
	timestamp     uint32
	payloadType   uint8
	dtlsSeq       uint16
	iceSeq        uint16
	stunSeq       uint16
	handshakeDone bool
	handshakeStep int
}

func NewWebRTCMask() *WebRTCMask {
	ssrcBytes := make([]byte, 4)
	rand.Read(ssrcBytes)
	ssrc := binary.BigEndian.Uint32(ssrcBytes)

	seqBytes := make([]byte, 2)
	rand.Read(seqBytes)
	sequence := binary.BigEndian.Uint16(seqBytes)

	return &WebRTCMask{
		ssrc:          ssrc,
		sequence:      sequence,
		timestamp:     uint32(time.Now().UnixNano() / 1e6),
		payloadType:   111,
		dtlsSeq:       0,
		iceSeq:        0,
		stunSeq:       0,
		handshakeDone: false,
		handshakeStep: 0,
	}
}

func (w *WebRTCMask) Wrap(payload []byte) []byte {
	if !w.handshakeDone && w.handshakeStep < 10 {
		return w.simulateHandshake()
	}

	w.handshakeDone = true

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
		binary.BigEndian.PutUint16(extData[0:2], 0xBEDE)
		binary.BigEndian.PutUint16(extData[2:4], uint16(extLen-4))
		rand.Read(extData[4:])
	}

	w.sequence++
	w.timestamp += uint32(len(payload)) / 2

	return w.marshalHeader(header, extData, payload)
}

func (w *WebRTCMask) simulateHandshake() []byte {
	w.handshakeStep++

	switch w.handshakeStep {
	case 1:
		return w.simulateSTUNBindingRequest()
	case 2:
		return w.simulateSTUNBindingResponse()
	case 3, 4, 5:
		return w.simulateDTLSHandshake()
	case 6:
		return w.simulateICEConnectivityCheck()
	case 7, 8:
		return w.simulateSRTPKeying()
	default:
		return w.simulateRTPPacket(nil)
	}
}

func (w *WebRTCMask) simulateSTUNBindingRequest() []byte {
	buf := make([]byte, 20)
	binary.BigEndian.PutUint16(buf[0:2], 0x0001)
	binary.BigEndian.PutUint16(buf[2:4], 0)
	binary.BigEndian.PutUint32(buf[4:8], 0x2112A442)
	rand.Read(buf[8:20])
	return buf
}

func (w *WebRTCMask) simulateSTUNBindingResponse() []byte {
	buf := make([]byte, 20+8)
	binary.BigEndian.PutUint16(buf[0:2], 0x0101)
	binary.BigEndian.PutUint16(buf[2:4], 8)
	binary.BigEndian.PutUint32(buf[4:8], 0x2112A442)
	rand.Read(buf[8:20])
	binary.BigEndian.PutUint16(buf[20:22], 0x0020)
	binary.BigEndian.PutUint16(buf[22:24], 4)
	binary.BigEndian.PutUint32(buf[24:28], 0x00000001)
	return buf
}

func (w *WebRTCMask) simulateDTLSHandshake() []byte {
	w.dtlsSeq++

	buf := make([]byte, 13+64)

	buf[0] = 22
	buf[1] = 0xFE
	buf[2] = 0xFD

	binary.BigEndian.PutUint16(buf[3:5], w.dtlsSeq)

	buf[5] = 0x00
	buf[6] = 0x00
	buf[7] = 0x00
	buf[8] = 0x00

	handshakeType := byte(1 + (w.handshakeStep-3)%3)
	buf[13] = handshakeType

	rand.Read(buf[14:78])

	crc := byte(0)
	for i := 0; i < len(buf); i++ {
		crc ^= buf[i]
	}
	buf = append(buf, crc)

	return buf
}

func (w *WebRTCMask) simulateICEConnectivityCheck() []byte {
	w.iceSeq++

	buf := make([]byte, 24)

	buf[0] = 0x01
	buf[1] = 0x00

	binary.BigEndian.PutUint16(buf[2:4], w.iceSeq)

	rand.Read(buf[4:12])

	binary.BigEndian.PutUint32(buf[12:16], w.ssrc)

	priority := uint32(1862270975)
	binary.BigEndian.PutUint32(buf[16:20], priority)

	copy(buf[20:24], []byte("ICE"))

	return buf
}

func (w *WebRTCMask) simulateSRTPKeying() []byte {
	buf := make([]byte, 80)

	buf[0] = 0x14
	buf[1] = 0x00

	rand.Read(buf[2:34])

	binary.BigEndian.PutUint32(buf[34:38], w.ssrc)

	rand.Read(buf[38:78])

	crc := byte(0)
	for i := 0; i < 78; i++ {
		crc ^= buf[i]
	}
	buf[78] = crc
	buf[79] = 0x00

	return buf
}

func (w *WebRTCMask) simulateRTPPacket(payload []byte) []byte {
	hasExt := false
	hasMarker := true

	randByte := make([]byte, 1)
	rand.Read(randByte)
	if randByte[0]&1 == 1 {
		hasExt = true
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
		extLen := 4 + int(randByte[0]%16)
		extData = make([]byte, extLen)
		binary.BigEndian.PutUint16(extData[0:2], 0xBEDE)
		binary.BigEndian.PutUint16(extData[2:4], uint16(extLen-4))
		rand.Read(extData[4:])
	}

	w.sequence++
	w.timestamp += 30

	if payload == nil {
		payload = make([]byte, 10+int(randByte[0]%50))
		rand.Read(payload)
	}

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

	payloadType := data[1] & 0x7F

	if payloadType == 111 {
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

	if len(data) >= 20 {
		magicCookie := binary.BigEndian.Uint32(data[4:8])
		if magicCookie == 0x2112A442 {
			msgLen := binary.BigEndian.Uint16(data[2:4])
			if len(data) >= 20+int(msgLen) {
				return data[20+int(msgLen):], nil
			}
		}
	}

	if len(data) > 13 && data[0] == 22 {
		if len(data) >= 13+64 {
			return data[13+64:], nil
		}
	}

	if len(data) > 24 && data[20] == 'I' && data[21] == 'C' && data[22] == 'E' {
		return data[24:], nil
	}

	if len(data) > 34 && data[0] == 0x14 {
		return data[80:], nil
	}

	return data[12:], nil
}

func (w *WebRTCMask) ID() string { return "webrtc" }

func (w *WebRTCMask) ResetHandshake() {
	w.handshakeDone = false
	w.handshakeStep = 0
	w.dtlsSeq = 0
	w.iceSeq = 0
	w.stunSeq = 0
}

func (w *WebRTCMask) IsHandshakeComplete() bool {
	return w.handshakeDone
}
