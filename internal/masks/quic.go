package masks

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"log"
	"sync"
	"time"
)

type CongestionControl struct {
	cwnd       uint32
	ssthresh   uint32
	rtt        time.Duration
	rttVar     time.Duration
	packetLoss bool
	mu         sync.RWMutex
}

func NewCongestionControl() *CongestionControl {
	return &CongestionControl{
		cwnd:     10,
		ssthresh: 65535,
		rtt:      30 * time.Millisecond,
	}
}

func (cc *CongestionControl) OnPacketSent(packetNum uint64, size int) {
	cc.mu.Lock()
	defer cc.mu.Unlock()
}

func (cc *CongestionControl) OnAckReceived(ackTime time.Duration) {
	cc.mu.Lock()
	defer cc.mu.Unlock()

	rtt := ackTime
	cc.rtt = (cc.rtt*7 + rtt) / 8

	if cc.cwnd < cc.ssthresh {
		cc.cwnd += 1
	} else {
		cc.cwnd += 1 / cc.cwnd
	}

	if cc.cwnd > 1000 {
		cc.cwnd = 1000
	}
}

func (cc *CongestionControl) OnPacketLoss() {
	cc.mu.Lock()
	defer cc.mu.Unlock()

	cc.ssthresh = cc.cwnd / 2
	if cc.ssthresh < 2 {
		cc.ssthresh = 2
	}
	cc.cwnd = 1
	cc.packetLoss = true
}

func (cc *CongestionControl) GetWindow() uint32 {
	cc.mu.RLock()
	defer cc.mu.RUnlock()
	return cc.cwnd
}

func (cc *CongestionControl) GetRTT() time.Duration {
	cc.mu.RLock()
	defer cc.mu.RUnlock()
	return cc.rtt
}

type QUICTransport struct {
	cc           *CongestionControl
	packetNum    uint64
	lastAck      uint64
	sentPackets  map[uint64]time.Time
	packetLosses int
	mu           sync.RWMutex
}

func NewQUICTransport() *QUICTransport {
	return &QUICTransport{
		cc:          NewCongestionControl(),
		packetNum:   0,
		lastAck:     0,
		sentPackets: make(map[uint64]time.Time),
	}
}

func (q *QUICTransport) SendPacket(data []byte) []byte {
	q.mu.Lock()
	defer q.mu.Unlock()

	q.packetNum++
	packetNum := q.packetNum

	q.sentPackets[packetNum] = time.Now()

	header := make([]byte, 17)
	header[0] = 0xC0 | 0x00
	binary.BigEndian.PutUint32(header[1:5], 0x00000001)
	binary.BigEndian.PutUint64(header[5:13], packetNum)

	window := q.cc.GetWindow()
	binary.BigEndian.PutUint32(header[13:17], window)

	payload := make([]byte, len(data)+4)
	binary.BigEndian.PutUint32(payload[0:4], uint32(len(data)))
	copy(payload[4:], data)

	return append(header, payload...)
}

func (q *QUICTransport) ProcessAck(ackNum uint64, ackDelay time.Duration) {
	q.mu.Lock()
	defer q.mu.Unlock()

	if ackNum <= q.lastAck {
		return
	}

	for i := q.lastAck + 1; i <= ackNum; i++ {
		if sendTime, ok := q.sentPackets[i]; ok {
			rtt := time.Since(sendTime)
			q.cc.OnAckReceived(rtt)
			delete(q.sentPackets, i)
		}
	}

	q.lastAck = ackNum
}

func (q *QUICTransport) DetectLoss() {
	q.mu.Lock()
	defer q.mu.Unlock()

	now := time.Now()
	for packetNum, sendTime := range q.sentPackets {
		if now.Sub(sendTime) > q.cc.GetRTT()*3 {
			q.cc.OnPacketLoss()
			delete(q.sentPackets, packetNum)
			q.packetLosses++
		}
	}
}

func (q *QUICTransport) GetStats() map[string]interface{} {
	q.mu.RLock()
	defer q.mu.RUnlock()

	return map[string]interface{}{
		"cwnd":          q.cc.GetWindow(),
		"rtt_ms":        q.cc.GetRTT().Milliseconds(),
		"packet_num":    q.packetNum,
		"packet_losses": q.packetLosses,
		"sent_pending":  len(q.sentPackets),
	}
}

type QUICMask struct {
	destConnID      []byte
	srcConnID       []byte
	packetNum       uint64
	version         uint32
	packetNumCipher cipher.AEAD
	secret          []byte
	handshakeDone   bool
	handshakeStep   int
	initialSecret   []byte
	handshakeSecret []byte
	oneRTTSecret    []byte
	transportParams []byte
	connectionID    [20]byte
	scid            []byte
	dcid            []byte
	transport       *QUICTransport
	congestionCtrl  *CongestionControl
	lastAckTime     time.Time
}

func NewQUICMask() *QUICMask {
	destID := make([]byte, 8)
	srcID := make([]byte, 8)
	scid := make([]byte, 8)
	dcid := make([]byte, 8)
	initialSecret := make([]byte, 32)
	handshakeSecret := make([]byte, 32)
	oneRTTSecret := make([]byte, 32)
	secret := make([]byte, 32)

	rand.Read(destID)
	rand.Read(srcID)
	rand.Read(scid)
	rand.Read(dcid)
	rand.Read(initialSecret)
	rand.Read(handshakeSecret)
	rand.Read(oneRTTSecret)
	rand.Read(secret)

	block, _ := aes.NewCipher(secret)
	aead, _ := cipher.NewGCM(block)

	transportParams := make([]byte, 64)
	rand.Read(transportParams)
	binary.BigEndian.PutUint32(transportParams[0:4], 0x00000001)
	binary.BigEndian.PutUint32(transportParams[4:8], 0x00001000)
	binary.BigEndian.PutUint32(transportParams[8:12], 0x00002000)

	var connID [20]byte
	rand.Read(connID[:])

	return &QUICMask{
		destConnID:      destID,
		srcConnID:       srcID,
		scid:            scid,
		dcid:            dcid,
		version:         0x00000001,
		packetNum:       0,
		packetNumCipher: aead,
		secret:          secret,
		handshakeDone:   false,
		handshakeStep:   0,
		initialSecret:   initialSecret,
		handshakeSecret: handshakeSecret,
		oneRTTSecret:    oneRTTSecret,
		transportParams: transportParams,
		connectionID:    connID,
		transport:       NewQUICTransport(),
		congestionCtrl:  NewCongestionControl(),
		lastAckTime:     time.Now(),
	}
}

func (q *QUICMask) Wrap(payload []byte) []byte {
	q.transport.DetectLoss()

	if !q.handshakeDone && q.handshakeStep < 8 {
		return q.simulateHandshake()
	}

	q.handshakeDone = true
	return q.transport.SendPacket(payload)
}

func (q *QUICMask) simulateHandshake() []byte {
	q.handshakeStep++

	switch q.handshakeStep {
	case 1:
		return q.simulateInitialPacket()
	case 2:
		return q.simulateRetryPacket()
	case 3, 4:
		return q.simulateHandshakePacket()
	case 5, 6:
		return q.simulateZeroRTTPacket()
	default:
		return q.simulateOneRTTPacket(nil)
	}
}

func (q *QUICMask) simulateInitialPacket() []byte {
	headerLen := 1 + 4 + 8 + 8 + 8 + 16
	buf := make([]byte, headerLen)

	buf[0] = 0xC0 | 0x00

	binary.BigEndian.PutUint32(buf[1:5], q.version)
	copy(buf[5:13], q.destConnID)
	copy(buf[13:21], q.srcConnID)

	tokenLen := uint8(0)
	buf[21] = tokenLen

	packetNumLen := uint8(4)
	buf[22] = packetNumLen

	nonce := make([]byte, 12)
	rand.Read(nonce)

	packetNumBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(packetNumBytes, q.packetNum)
	encryptedPN := q.packetNumCipher.Seal(nil, nonce, packetNumBytes, nil)

	offset := 23
	copy(buf[offset:offset+len(encryptedPN)], encryptedPN)
	offset += len(encryptedPN)
	copy(buf[offset:offset+12], nonce)
	offset += 12

	cryptoFrame := make([]byte, 100)
	cryptoFrame[0] = 0x06
	binary.BigEndian.PutUint64(cryptoFrame[1:9], uint64(time.Now().UnixNano()))
	rand.Read(cryptoFrame[9:])
	copy(buf[offset:offset+len(cryptoFrame)], cryptoFrame)

	q.packetNum++
	return buf
}

func (q *QUICMask) simulateRetryPacket() []byte {
	buf := make([]byte, 1+4+8+8+8+16)

	buf[0] = 0xC0 | 0x01

	binary.BigEndian.PutUint32(buf[1:5], q.version)
	copy(buf[5:13], q.destConnID)
	copy(buf[13:21], q.srcConnID)

	retryToken := make([]byte, 16)
	rand.Read(retryToken)
	copy(buf[21:37], retryToken)

	q.packetNum++
	return buf
}

func (q *QUICMask) simulateHandshakePacket() []byte {
	headerLen := 1 + 4 + 8 + 8 + 4 + 16
	buf := make([]byte, headerLen)

	buf[0] = 0xC0 | 0x02

	binary.BigEndian.PutUint32(buf[1:5], q.version)
	copy(buf[5:13], q.destConnID)
	copy(buf[13:21], q.srcConnID)

	packetNum := uint32(q.packetNum)
	binary.BigEndian.PutUint32(buf[21:25], packetNum)

	nonce := make([]byte, 12)
	rand.Read(nonce)
	copy(buf[25:37], nonce)

	cryptoFrame := make([]byte, 150)
	cryptoFrame[0] = 0x06
	cryptoFrame[1] = 0x00
	cryptoFrame[2] = 0x00
	binary.BigEndian.PutUint16(cryptoFrame[3:5], uint16(len(q.transportParams)))
	copy(cryptoFrame[5:5+len(q.transportParams)], q.transportParams)
	rand.Read(cryptoFrame[5+len(q.transportParams):])

	buf = append(buf, cryptoFrame...)

	q.packetNum++
	return buf
}

func (q *QUICMask) simulateZeroRTTPacket() []byte {
	headerLen := 1 + 8 + 4 + 16
	buf := make([]byte, headerLen)

	buf[0] = 0xC0 | 0x03

	copy(buf[1:9], q.srcConnID)

	packetNum := uint32(q.packetNum)
	binary.BigEndian.PutUint32(buf[9:13], packetNum)

	nonce := make([]byte, 12)
	rand.Read(nonce)
	copy(buf[13:25], nonce)

	streamFrame := make([]byte, 64)
	streamFrame[0] = 0x08
	streamFrame[1] = 0x00
	streamFrame[2] = 0x00
	rand.Read(streamFrame[3:])
	buf = append(buf, streamFrame...)

	q.packetNum++
	return buf
}

func (q *QUICMask) simulateOneRTTPacket(payload []byte) []byte {
	if payload == nil {
		payload = make([]byte, 32+int(q.packetNum%100))
		rand.Read(payload)
	}

	encryptedPayload := make([]byte, len(payload))
	for i := range payload {
		encryptedPayload[i] = payload[i] ^ q.oneRTTSecret[i%32]
	}

	return q.transport.SendPacket(encryptedPayload)
}

func (q *QUICMask) simulateConnectionClose() []byte {
	buf := make([]byte, 1+4+8+8+8)

	buf[0] = 0xC0 | 0x02

	binary.BigEndian.PutUint32(buf[1:5], q.version)
	copy(buf[5:13], q.destConnID)
	copy(buf[13:21], q.srcConnID)

	errorCode := uint64(0x00000000)
	binary.BigEndian.PutUint64(buf[21:29], errorCode)

	reason := []byte("connection closed")
	copy(buf[29:29+len(reason)], reason)

	return buf
}

func (q *QUICMask) Unwrap(data []byte) ([]byte, error) {
	if len(data) < 5 {
		return nil, ErrInvalidPacket
	}

	headerForm := (data[0] & 0x80) >> 7

	if headerForm == 1 {
		if len(data) < 21 {
			return nil, ErrInvalidPacket
		}

		packetType := data[0] & 0x3F

		if packetType == 0x00 {
			if len(data) < 17 {
				return nil, ErrInvalidPacket
			}
			packetNum := binary.BigEndian.Uint64(data[5:13])
			ackWindow := binary.BigEndian.Uint32(data[13:17])

			q.transport.ProcessAck(packetNum, time.Since(q.lastAckTime))
			q.lastAckTime = time.Now()

			log.Printf("[QUIC] ACK received: packet=%d, window=%d, cwnd=%d",
				packetNum, ackWindow, q.congestionCtrl.GetWindow())

			if len(data) > 17 {
				payloadLen := binary.BigEndian.Uint32(data[17:21])
				if len(data) >= 21+int(payloadLen) {
					return data[21 : 21+int(payloadLen)], nil
				}
			}
			return nil, nil
		}

		switch packetType {
		case 0x00:
			if len(data) > 23 {
				return q.processInitialPacket(data)
			}
		case 0x01:
			if len(data) > 37 {
				return q.processRetryPacket(data)
			}
		case 0x02:
			if len(data) > 25 {
				return q.processHandshakePacket(data)
			}
		case 0x03:
			if len(data) > 25 {
				return q.processZeroRTTPacket(data)
			}
		}

		if len(data) > 49 {
			return data[49:], nil
		}
		return data[21:], nil
	}

	if len(data) > 17 {
		return q.processShortPacket(data)
	}

	return nil, ErrInvalidPacket
}

func (q *QUICMask) processInitialPacket(data []byte) ([]byte, error) {
	tokenLen := int(data[21])
	offset := 22 + tokenLen

	packetNumLen := int(data[offset])
	offset++

	offset += packetNumLen
	offset += 12

	if offset >= len(data) {
		return nil, ErrInvalidPacket
	}

	frameType := data[offset]
	if frameType == 0x06 {
		offset++
		if offset+2 > len(data) {
			return nil, ErrInvalidPacket
		}
		frameLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
		offset += 2 + frameLen
	}

	if offset < len(data) {
		return data[offset:], nil
	}
	return nil, nil
}

func (q *QUICMask) processRetryPacket(data []byte) ([]byte, error) {
	if len(data) > 37 {
		return data[37:], nil
	}
	return nil, nil
}

func (q *QUICMask) processHandshakePacket(data []byte) ([]byte, error) {
	offset := 25

	if offset+12 > len(data) {
		return nil, ErrInvalidPacket
	}
	offset += 12

	if offset >= len(data) {
		return nil, nil
	}

	frameType := data[offset]
	if frameType == 0x06 {
		offset++
		if offset+2 > len(data) {
			return nil, ErrInvalidPacket
		}
		frameLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
		offset += 2 + frameLen
	}

	if offset < len(data) {
		return data[offset:], nil
	}
	return nil, nil
}

func (q *QUICMask) processZeroRTTPacket(data []byte) ([]byte, error) {
	offset := 25

	if offset+12 > len(data) {
		return nil, ErrInvalidPacket
	}
	offset += 12

	if offset >= len(data) {
		return nil, nil
	}

	frameType := data[offset]
	if frameType == 0x08 || frameType == 0x09 {
		offset++
		if offset+2 > len(data) {
			return nil, ErrInvalidPacket
		}
		frameLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
		offset += 2 + frameLen
	}

	if offset < len(data) {
		return data[offset:], nil
	}
	return nil, nil
}

func (q *QUICMask) processShortPacket(data []byte) ([]byte, error) {
	if len(data) < 5 {
		return nil, ErrInvalidPacket
	}

	packetNumLen := int((data[0] & 0x03)) + 1
	offset := 1 + packetNumLen + 12

	if offset >= len(data) {
		return nil, ErrInvalidPacket
	}

	tagLen := 16
	if len(data) > offset+tagLen {
		return data[offset : len(data)-tagLen], nil
	}

	return data[offset:], nil
}

func (q *QUICMask) ID() string { return "quic" }

func (q *QUICMask) ResetHandshake() {
	q.handshakeDone = false
	q.handshakeStep = 0
	q.packetNum = 0
}

func (q *QUICMask) IsHandshakeComplete() bool {
	return q.handshakeDone
}

func (q *QUICMask) GetConnectionID() []byte {
	return q.connectionID[:]
}

func (q *QUICMask) GetCongestionStats() map[string]interface{} {
	return q.transport.GetStats()
}
