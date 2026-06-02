package masks

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"log"
)

type TLSMask struct {
	sequence         uint16
	sni              string
	cert             []byte
	handshakeDone    bool
	handshakeStep    int
	sessionID        [32]byte
	http2StreamID    uint32
	http2Initialized bool
}

func NewTLSMask() *TLSMask {
	m := &TLSMask{
		sequence:         0,
		sni:              "www.google.com",
		handshakeDone:    false,
		handshakeStep:    0,
		http2StreamID:    1,
		http2Initialized: false,
	}

	rand.Read(m.sessionID[:])
	m.loadRealCert()

	return m
}

func (t *TLSMask) loadRealCert() {
	conn, err := tls.Dial("tcp", "www.google.com:443", &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		log.Printf("TLS: Failed to get real cert: %v", err)
		t.cert = t.generateFakeCert()
		return
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) > 0 {
		t.cert = state.PeerCertificates[0].Raw
		log.Printf("TLS: Loaded real certificate from google.com")
	} else {
		t.cert = t.generateFakeCert()
	}
}

func (t *TLSMask) generateFakeCert() []byte {
	cert := make([]byte, 1024)
	rand.Read(cert)
	cert[0] = 0x30
	cert[1] = 0x82
	binary.BigEndian.PutUint16(cert[2:4], 1000)
	return cert
}

func (t *TLSMask) Wrap(payload []byte) []byte {
	if !t.handshakeDone && t.handshakeStep < 6 {
		return t.simulateHandshake()
	}

	t.handshakeDone = true
	return t.simulateDataPacket(payload)
}

func (t *TLSMask) simulateHandshake() []byte {
	t.handshakeStep++

	switch t.handshakeStep {
	case 1:
		return t.simulateClientHello()
	case 2:
		return t.simulateServerHello()
	case 3:
		return t.simulateCertificate()
	case 4:
		return t.simulateServerKeyExchange()
	case 5:
		return t.simulateClientKeyExchange()
	default:
		return t.simulateChangeCipherSpec()
	}
}

func (t *TLSMask) simulateClientHello() []byte {
	buf := make([]byte, 200)

	buf[0] = 0x16
	buf[1] = 0x03
	buf[2] = 0x03
	binary.BigEndian.PutUint16(buf[3:5], uint16(len(buf)-5))

	buf[5] = 0x01
	putUint24(buf[6:9], uint32(len(buf)-9))

	buf[9] = 0x03
	buf[10] = 0x03

	rand.Read(buf[11:43])

	buf[43] = 32
	copy(buf[44:76], t.sessionID[:])

	binary.BigEndian.PutUint16(buf[76:78], 2)
	binary.BigEndian.PutUint16(buf[78:80], 0xC02F)

	buf[80] = 1
	buf[81] = 0

	binary.BigEndian.PutUint16(buf[82:84], 2)
	binary.BigEndian.PutUint16(buf[84:86], 0x0000)
	sniLen := 2 + len(t.sni)
	binary.BigEndian.PutUint16(buf[86:88], uint16(sniLen))
	binary.BigEndian.PutUint16(buf[88:90], uint16(len(t.sni)))
	copy(buf[90:90+len(t.sni)], t.sni)

	t.sequence++
	return buf[:90+len(t.sni)]
}

func (t *TLSMask) simulateServerHello() []byte {
	buf := make([]byte, 79)

	buf[0] = 0x16
	buf[1] = 0x03
	buf[2] = 0x03
	binary.BigEndian.PutUint16(buf[3:5], 58)

	buf[5] = 0x02
	putUint24(buf[6:9], 54)

	buf[9] = 0x03
	buf[10] = 0x03
	rand.Read(buf[11:43])
	buf[43] = 32
	copy(buf[44:76], t.sessionID[:])

	binary.BigEndian.PutUint16(buf[76:78], 0xC02F)
	buf[78] = 0

	t.sequence++
	return buf[:79]
}

func (t *TLSMask) simulateCertificate() []byte {
	certLen := len(t.cert)
	buf := make([]byte, 15+certLen)

	buf[0] = 0x16
	buf[1] = 0x03
	buf[2] = 0x03
	binary.BigEndian.PutUint16(buf[3:5], uint16(9+certLen))

	buf[5] = 0x0B
	putUint24(buf[6:9], uint32(5+certLen))

	putUint24(buf[9:12], uint32(certLen))
	putUint24(buf[12:15], uint32(certLen))
	copy(buf[15:15+certLen], t.cert)

	t.sequence++
	return buf[:15+certLen]
}

func (t *TLSMask) simulateServerKeyExchange() []byte {
	buf := make([]byte, 141)

	buf[0] = 0x16
	buf[1] = 0x03
	buf[2] = 0x03
	binary.BigEndian.PutUint16(buf[3:5], 140)

	buf[5] = 0x0C
	putUint24(buf[6:9], 136)

	rand.Read(buf[9:141])

	t.sequence++
	return buf[:141]
}

func (t *TLSMask) simulateClientKeyExchange() []byte {
	buf := make([]byte, 45)

	buf[0] = 0x16
	buf[1] = 0x03
	buf[2] = 0x03
	binary.BigEndian.PutUint16(buf[3:5], 40)

	buf[5] = 0x10
	putUint24(buf[6:9], 36)

	rand.Read(buf[9:45])

	t.sequence++
	return buf[:45]
}

func (t *TLSMask) simulateChangeCipherSpec() []byte {
	buf := make([]byte, 6)

	buf[0] = 0x14
	buf[1] = 0x03
	buf[2] = 0x03
	binary.BigEndian.PutUint16(buf[3:5], 1)
	buf[5] = 0x01

	t.sequence++
	return buf[:6]
}

func (t *TLSMask) simulateDataPacket(payload []byte) []byte {
	if len(payload) == 0 {
		payload = make([]byte, 100)
		rand.Read(payload)
	}

	if !t.http2Initialized {
		t.http2Initialized = true
		preface := GenerateHTTP2Preface()
		settings := NewHTTP2SettingsFrame()
		combined := append(preface, settings...)
		return t.wrapInTLSRecord(combined)
	}

	var http2Data []byte

	switch t.http2StreamID % 4 {
	case 1:
		headers := t.generateHTTP2Headers()
		http2Data = NewHTTP2HeadersFrame(t.http2StreamID, headers, false)
	case 2:
		windowUpdate := NewHTTP2WindowUpdateFrame(0, 65535)
		ping := NewHTTP2PingFrame()
		http2Data = append(windowUpdate, ping...)
	case 3:
		http2Data = NewHTTP2DataFrame(t.http2StreamID, payload, false)
	case 0:
		http2Data = NewHTTP2DataFrame(t.http2StreamID, payload, true)
		t.http2StreamID += 2
	}

	t.http2StreamID++
	return t.wrapInTLSRecord(http2Data)
}

func (t *TLSMask) wrapInTLSRecord(data []byte) []byte {
	buf := make([]byte, 5+len(data))
	buf[0] = 0x17
	buf[1] = 0x03
	buf[2] = 0x03
	binary.BigEndian.PutUint16(buf[3:5], uint16(len(data)))
	copy(buf[5:], data)
	return buf
}

func (t *TLSMask) generateHTTP2Headers() []byte {
	headers := []byte{
		0x82, 0x84, 0x87, 0x41, 0x8c, 0xf1, 0xe3, 0xc0,
		0x5f, 0x0a, 0x83, 0xce, 0x65, 0x0f, 0x8b, 0x9a,
		0x10, 0x3c, 0x2d, 0x4b, 0x1a, 0x0f, 0x8b, 0x9a,
	}
	rand.Read(headers[len(headers)-8:])
	return headers
}

func (t *TLSMask) Unwrap(data []byte) ([]byte, error) {
	if len(data) < 5 {
		return nil, ErrInvalidPacket
	}

	contentType := data[0]
	if contentType == 0x16 || contentType == 0x17 || contentType == 0x14 {
		recordLen := int(binary.BigEndian.Uint16(data[3:5]))
		if len(data) < 5+recordLen {
			return nil, ErrInvalidPacket
		}
		return data[5 : 5+recordLen], nil
	}

	return data, nil
}

func (t *TLSMask) ID() string { return "tls" }
