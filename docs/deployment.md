# L7-Shred Deployment Guide

## Server Setup

### Requirements
- Linux (kernel 4.9+)
- 512MB RAM
- Open port 443 (TCP+UDP)

### Installation

```bash
# Download binary
wget https://github.com/l7-shred/core/releases/latest/l7-shred-server-linux-amd64
chmod +x l7-shred-server-linux-amd64

# Generate secret key
openssl rand -base64 32 > secret.key

# Edit config
vim configs/server.standalone.json

# Run
./l7-shred-server-linux-amd64 -config configs/server.standalone.json