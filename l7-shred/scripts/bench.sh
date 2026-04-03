#!/bin/bash

set -e

echo "L7-Shred Performance Benchmark"

if ! command -v iperf3 &> /dev/null; then
    echo "Installing iperf3..."
    sudo apt-get update && sudo apt-get install -y iperf3
fi

echo "Starting server in background..."
./bin/l7-shred-server -config configs/server.standalone.json &
SERVER_PID=$!
sleep 2

echo "Running iperf3 test (30 seconds)..."
iperf3 -c 127.0.0.1 -p 443 -t 30 -J > /tmp/iperf-result.json

echo "Running latency test..."
ping -c 100 127.0.0.1 > /tmp/ping-result.txt

echo "Calculating throughput..."
THROUGHPUT=$(jq '.end.sum_received.bits_per_second' /tmp/iperf-result.json)
THROUGHPUT_MBPS=$(echo "scale=2; $THROUGHPUT / 1000000" | bc)

echo "Calculating average latency..."
AVG_LATENCY=$(grep "avg" /tmp/ping-result.txt | cut -d'/' -f5)

echo "=== RESULTS ==="
echo "Throughput: ${THROUGHPUT_MBPS} Mbps"
echo "Average Latency: ${AVG_LATENCY} ms"

echo "Testing concurrent connections (100 clients)..."
for i in {1..100}; do
    (./bin/l7-shred-client -config configs/client.desktop.json &)
    CLIENT_PIDS[$i]=$!
done

sleep 10

for pid in ${CLIENT_PIDS[@]}; do
    kill $pid 2>/dev/null
done

echo "Concurrent test complete!"

kill $SERVER_PID
echo "Benchmark complete!"