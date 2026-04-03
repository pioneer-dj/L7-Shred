package utils

import (
	"crypto/sha256"
	"time"
)

type FingerprintRotator struct {
	index      int
	profiles   []string
	lastRotate time.Time
	interval   time.Duration
}

func NewFingerprintRotator(interval time.Duration) *FingerprintRotator {
	profiles := []string{
		"chrome_120",
		"firefox_120",
		"safari_16_0",
		"edge_120",
		"ios_17_0",
		"android_chrome_120",
	}

	return &FingerprintRotator{
		profiles: profiles,
		interval: interval,
	}
}

func (f *FingerprintRotator) GetCurrent() string {
	if time.Since(f.lastRotate) > f.interval {
		f.index = (f.index + 1) % len(f.profiles)
		f.lastRotate = time.Now()
	}
	return f.profiles[f.index]
}

func (f *FingerprintRotator) GenerateJA3() string {
	fingerprint := f.GetCurrent()
	hash := sha256.Sum256([]byte(fingerprint))
	return string(hash[:16])
}

func (f *FingerprintRotator) GenerateJA4() string {
	fingerprint := f.GetCurrent()
	hash := sha256.Sum256([]byte(fingerprint + time.Now().String()))
	return string(hash[:20])
}
