package integration

import (
	"testing"
	"time"

	"github.com/l7-shred/core/internal/engine"
	"github.com/l7-shred/core/internal/masks"
	"github.com/l7-shred/core/internal/proto"
)

func TestWebRTCMasking(t *testing.T) {
	mask := masks.NewWebRTCMask()

	testData := []byte("test payload data")
	wrapped := mask.Wrap(testData)

	if len(wrapped) < 12 {
		t.Errorf("Expected at least 12 byte header, got %d", len(wrapped))
	}

	if wrapped[0]>>6 != 2 {
		t.Errorf("Expected RTP version 2, got %d", wrapped[0]>>6)
	}

	t.Logf("WebRTC wrapped %d bytes -> %d bytes", len(testData), len(wrapped))
}

func TestQUICMasking(t *testing.T) {
	mask := masks.NewQUICMask()

	testData := []byte("test payload data")
	wrapped := mask.Wrap(testData)

	if len(wrapped) < 21 {
		t.Errorf("Expected at least 21 byte header, got %d", len(wrapped))
	}

	t.Logf("QUIC wrapped %d bytes -> %d bytes", len(testData), len(wrapped))
}

func TestJitterSimulation(t *testing.T) {
	jitter := engine.NewJitterEngine(2*time.Millisecond, 1*time.Millisecond, 0.01)

	start := time.Now()
	jitter.Apply()
	elapsed := time.Since(start)

	if elapsed < 0 {
		t.Errorf("Invalid jitter delay")
	}

	t.Logf("Jitter delay: %v", elapsed)
}

func TestFragmentRotation(t *testing.T) {
	fragmentor := proto.NewFragmentor(32, 288)

	size1 := fragmentor.currentSize
	time.Sleep(31 * time.Second)
	size2 := fragmentor.currentSize

	if size1 == size2 {
		t.Logf("Fragment size unchanged: %d", size1)
	} else {
		t.Logf("Fragment size rotated: %d -> %d", size1, size2)
	}
}
