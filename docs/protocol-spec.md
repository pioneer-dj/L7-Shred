# L7-Shred Protocol Specification v1.0

## Frame Format
+----------------+------+------------------+-----------------+
| Auth Token | Len | Encrypted Payload| Dynamic Padding |
| 32 bytes | 2 | Variable | 32-288 bytes |
+----------------+------+------------------+-----------------+
## Handshake (Noise XX)

1. Client sends ephemeral public key
2. Server responds with ephemeral + static public keys
3. Client sends static public key + payload
4. Session key derived via HKDF

## Masks

### WebRTC (UDP)
- RTP header (12 bytes)
- SSRC: random per session
- Sequence: monotonic

### QUIC (UDP)
- Header: 1+4+8+8 bytes
- Version: 1 (draft 34)
- Connection IDs: 8 bytes each

### Teams (UDP)
- 20 byte header
- Conference ID + Participant ID + Sequence

## Padding Algorithm
- Size: min 32, max 288 bytes
- Rotation: every 30 seconds
- Deterministic: based on session_id + time/30

## Jitter
- Mean: 2ms
- StdDev: 1ms
- Loss rate: 0.5%