package masks

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"time"
)

type DNSOverHTTPSMask struct {
	queryID uint16
	random  []byte
}

func NewDNSOverHTTPSMask() *DNSOverHTTPSMask {
	random := make([]byte, 32)
	rand.Read(random)

	return &DNSOverHTTPSMask{
		queryID: 0,
		random:  random,
	}
}

func (d *DNSOverHTTPSMask) Wrap(payload []byte) []byte {
	d.queryID++

	dnsMsg := make([]byte, 12+len(payload))

	binary.BigEndian.PutUint16(dnsMsg[0:2], d.queryID) // ID
	binary.BigEndian.PutUint16(dnsMsg[2:4], 0x0100)    // Flags: QR=0, OPCODE=0, AA=0, TC=0, RD=1
	binary.BigEndian.PutUint16(dnsMsg[4:6], 1)         // QDCOUNT
	binary.BigEndian.PutUint16(dnsMsg[6:8], 0)         // ANCOUNT
	binary.BigEndian.PutUint16(dnsMsg[8:10], 0)        // NSCOUNT
	binary.BigEndian.PutUint16(dnsMsg[10:12], 0)       // ARCOUNT

	copy(dnsMsg[12:], payload)

	httpReq := &bytes.Buffer{}
	fmt.Fprintf(httpReq, "POST /dns-query HTTP/2\r\n")
	fmt.Fprintf(httpReq, "Host: dns.google\r\n")
	fmt.Fprintf(httpReq, "Content-Type: application/dns-message\r\n")
	fmt.Fprintf(httpReq, "Content-Length: %d\r\n", len(dnsMsg))
	fmt.Fprintf(httpReq, "Date: %s\r\n", time.Now().UTC().Format("Mon, 02 Jan 2006 15:04:05 GMT"))
	fmt.Fprintf(httpReq, "\r\n")
	httpReq.Write(dnsMsg)

	return httpReq.Bytes()
}

func (d *DNSOverHTTPSMask) Unwrap(data []byte) ([]byte, error) {
	idx := bytes.Index(data, []byte("\r\n\r\n"))
	if idx == -1 {
		return nil, ErrInvalidPacket
	}
	body := data[idx+4:]
	if len(body) < 12 {
		return nil, ErrInvalidPacket
	}
	return body[12:], nil
}

func (d *DNSOverHTTPSMask) ID() string { return "doh" }

