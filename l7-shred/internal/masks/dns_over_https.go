package masks

import (
	"crypto/rand"
	"encoding/base64"
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

	dnsMsg[0] = byte(d.queryID >> 8)
	dnsMsg[1] = byte(d.queryID & 0xFF)
	dnsMsg[2] = 0x01
	dnsMsg[3] = 0x00
	dnsMsg[4] = 0x00
	dnsMsg[5] = 0x01
	dnsMsg[6] = 0x00
	dnsMsg[7] = 0x00
	dnsMsg[8] = 0x00
	dnsMsg[9] = 0x00
	dnsMsg[10] = 0x00
	dnsMsg[11] = 0x00

	copy(dnsMsg[12:], payload)

	encoded := base64.RawURLEncoding.EncodeToString(dnsMsg)

	httpBody := []byte("{\"dns\":\"" + encoded + "\"}")

	return httpBody
}
