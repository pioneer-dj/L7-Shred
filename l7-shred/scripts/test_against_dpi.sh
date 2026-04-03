#!/bin/bash

set -e

echo "L7-Shred DPI Testing Suite"

if ! command -v nDPI &> /dev/null; then
    echo "Installing nDPI..."
    git clone https://github.com/ntop/nDPI.git /tmp/nDPI
    cd /tmp/nDPI
    ./autogen.sh
    make
    sudo make install
    cd -
fi

echo "Starting test server..."
./bin/l7-shred-server -config configs/server.standalone.json &
SERVER_PID=$!
sleep 2

echo "Starting test client..."
./bin/l7-shred-client -config configs/client.desktop.json &
CLIENT_PID=$!
sleep 2

echo "Capturing traffic..."
sudo tcpdump -i lo -w /tmp/l7shred-test.pcap -G 30 -W 1 &
TCPDUMP_PID=$!

sleep 25

sudo kill $TCPDUMP_PID
kill $SERVER_PID $CLIENT_PID

echo "Analyzing with nDPI..."
ndpiReader -i /tmp/l7shred-test.pcap

echo "Analyzing with tcpdump patterns..."
tcpdump -r /tmp/l7shred-test.pcap -v | head -50

echo "Testing packet size distribution..."
tshark -r /tmp/l7shred-test.pcap -T fields -e frame.len | sort -n | uniq -c | head -30

echo "Testing inter-packet timing..."
tshark -r /tmp/l7shred-test.pcap -T fields -e frame.time_relative | awk 'NR>1{print $1-prev} {prev=$1}' | head -30

echo "Test complete! Check if protocol was detected as unknown/WebRTC"