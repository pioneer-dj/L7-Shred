# L7-Shred Architecture

## Overview
L7-Shred is a next-generation anti-DPI protocol that operates at Layer 7 with dynamic fragmentation, temporal jitter, and post-quantum cryptography.

## Core Components

### 1. Shred Engine
- Dynamic fragmentation (32-288 bytes)
- Traffic shaping for torrents
- Temporal jitter injection

### 2. Masking Layer
- 7+ protocol mimics (WebRTC, QUIC, Teams, WinUpdate, DNS-over-HTTPS, STUN, Zoom)
- Automatic protocol rotation every 5 minutes
- Realistic header injection

### 3. Cryptography
- Noise Protocol Framework (XX pattern)
- Post-quantum Kyber768 + X25519 hybrid
- AES-256-GCM / ChaCha20-Poly1305

### 4. Transport
- Dual-mode (TCP + UDP)
- Auto-fallback
- Ghost handshake (silent reject)

## Security Properties
- Perfect Forward Secrecy
- Replay attack protection
- No TLS fingerprints (JA3/JA4)
- No magic bytes

## Performance
- Throughput: 1.8 GB/s (AES-NI)
- Latency: 1 RTT handshake
- Overhead: ~15%