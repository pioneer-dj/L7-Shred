package engine

import (
	"crypto/rand"
	"log"
	"time"
)

type BackgroundTraffic struct {
	enabled  bool
	ticker   *time.Ticker
	stopChan chan struct{}
	sendFunc func([]byte) error
	interval time.Duration
	jitter   time.Duration
}

type BackgroundConfig struct {
	Enabled   bool
	Interval  time.Duration
	JitterMs  int
	Randomize bool
}

func DefaultBackgroundConfig() *BackgroundConfig {
	return &BackgroundConfig{
		Enabled:   true,
		Interval:  30 * time.Second,
		JitterMs:  5000,
		Randomize: true,
	}
}

func NewBackgroundTraffic(sendFunc func([]byte) error, config *BackgroundConfig) *BackgroundTraffic {
	if config == nil {
		config = DefaultBackgroundConfig()
	}

	bt := &BackgroundTraffic{
		enabled:  config.Enabled,
		stopChan: make(chan struct{}),
		sendFunc: sendFunc,
		interval: config.Interval,
		jitter:   time.Duration(config.JitterMs) * time.Millisecond,
	}

	if bt.enabled {
		bt.start()
	}

	return bt
}

func (bt *BackgroundTraffic) start() {
	if bt.ticker != nil {
		return
	}

	interval := bt.interval
	if bt.jitter > 0 {
		jitterMs := time.Duration(randInt(0, int(bt.jitter.Milliseconds())))
		interval = bt.interval + jitterMs*time.Millisecond
	}

	bt.ticker = time.NewTicker(interval)

	go func() {
		log.Printf("[Background] Started background traffic (interval: %v)", bt.interval)
		for {
			select {
			case <-bt.ticker.C:
				bt.sendHeartbeat()
			case <-bt.stopChan:
				bt.ticker.Stop()
				log.Printf("[Background] Stopped background traffic")
				return
			}
		}
	}()
}

func (bt *BackgroundTraffic) Stop() {
	if bt.stopChan != nil {
		close(bt.stopChan)
	}
}

func (bt *BackgroundTraffic) sendHeartbeat() {
	switch randInt(1, 5) {
	case 1:
		bt.sendPing()
	case 2:
		bt.sendAPIRequest()
	case 3:
		bt.sendKeepAlive()
	case 4:
		bt.sendMetrics()
	}
}

func (bt *BackgroundTraffic) sendPing() {
	data := []byte("PING")
	if err := bt.sendFunc(data); err != nil {
		log.Printf("[Background] Ping send error: %v", err)
	}
}

func (bt *BackgroundTraffic) sendKeepAlive() {
	data := []byte{0x00, 0x00, 0x00, 0x00}
	if err := bt.sendFunc(data); err != nil {
		log.Printf("[Background] Keep-alive send error: %v", err)
	}
}

func (bt *BackgroundTraffic) sendAPIRequest() {
	payload := make([]byte, randInt(32, 128))
	rand.Read(payload)

	request := []byte("GET /api/v1/status HTTP/2.0\r\n")
	request = append(request, "Host: api.google.com\r\n"...)
	request = append(request, "User-Agent: Mozilla/5.0\r\n"...)
	request = append(request, "\r\n"...)
	request = append(request, payload...)

	if err := bt.sendFunc(request); err != nil {
		log.Printf("[Background] API request error: %v", err)
	}
}

func (bt *BackgroundTraffic) sendMetrics() {
	data := make([]byte, randInt(16, 64))
	rand.Read(data)

	metrics := []byte("{\"type\":\"telemetry\",\"data\":")
	metrics = append(metrics, data...)
	metrics = append(metrics, '}')

	if err := bt.sendFunc(metrics); err != nil {
		log.Printf("[Background] Metrics send error: %v", err)
	}
}

func randInt(min, max int) int {
	if min == max {
		return min
	}
	b := make([]byte, 4)
	rand.Read(b)
	n := int(b[0])<<24 | int(b[1])<<16 | int(b[2])<<8 | int(b[3])
	if n < 0 {
		n = -n
	}
	return min + (n % (max - min))
}
