package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	BytesReceived = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "l7shred_bytes_received_total",
			Help: "Total bytes received",
		},
		[]string{"mode", "protocol"},
	)
	
	BytesSent = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "l7shred_bytes_sent_total",
			Help: "Total bytes sent",
		},
		[]string{"mode", "protocol"},
	)
	
	ActiveSessions = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "l7shred_active_sessions",
			Help: "Number of active sessions",
		},
	)
	
	HandshakeDuration = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "l7shred_handshake_duration_seconds",
			Help:    "Handshake duration in seconds",
			Buckets: prometheus.DefBuckets,
		},
	)
	
	PacketsDropped = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "l7shred_packets_dropped_total",
			Help: "Total packets dropped by jitter",
		},
	)
	
	PaddingAdded = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "l7shred_padding_bytes_total",
			Help: "Total padding bytes added",
		},
	)
)

func RecordBytes(mode, protocol string, received, sent uint64) {
	BytesReceived.WithLabelValues(mode, protocol).Add(float64(received))
	BytesSent.WithLabelValues(mode, protocol).Add(float64(sent))
}

func UpdateSessions(count int) {
	ActiveSessions.Set(float64(count))
}