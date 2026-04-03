package e2e

import (
	"testing"
	"time"
	
	"github.com/l7-shred/core/internal/transport"
)

func TestEndToEnd(t *testing.T) {
	config := &transport.Config{
		ServerAddr: "localhost:8443",
		ListenAddr: "localhost:8443",
		Mode:       "tcp",
		SecretKey:  make([]byte, 32),
	}
	
	server, err := transport.NewInbound(config)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}
	
	if err := server.Start(); err != nil {
		t.Fatalf("Failed to start server: %v", err)
	}
	defer server.Stop()
	
	time.Sleep(100 * time.Millisecond)
	
	client, err := transport.NewOutbound(config)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	
	if err := client.Connect(); err != nil {
		t.Fatalf("Failed to connect client: %v", err)
	}
	defer client.Close()
	
	t.Log("E2E test passed")
}

func TestUDPEndToEnd(t *testing.T) {
	config := &transport.Config{
		ServerAddr: "localhost:8444",
		ListenAddr: "localhost:8444",
		Mode:       "udp",
		SecretKey:  make([]byte, 32),
	}
	
	server, err := transport.NewInbound(config)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}
	
	if err := server.Start(); err != nil {
		t.Fatalf("Failed to start server: %v", err)
	}
	defer server.Stop()
	
	time.Sleep(100 * time.Millisecond)
	
	client, err := transport.NewOutbound(config)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	
	if err := client.Connect(); err != nil {
		t.Fatalf("Failed to connect client: %v", err)
	}
	defer client.Close()
	
	t.Log("UDP E2E test passed")
}