package main

import (
	"flag"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"github.com/l7-shred/core/internal/engine"
	"github.com/l7-shred/core/internal/shred"
	"github.com/l7-shred/core/internal/transport"
	"github.com/l7-shred/core/internal/tun"
)

var (
	Version   = "dev"
	BuildTime = "unknown"
)

func main() {
	configPath := flag.String("config", "configs/client.desktop.json", "config file path")
	tunAddr := flag.String("tun", "10.0.0.2", "TUN interface IP address")
	version := flag.Bool("version", false, "show version")
	flag.Parse()

	if *version {
		log.Printf("L7-Shred Client v%s (built %s)", Version, BuildTime)
		return
	}

	log.Printf("Starting L7-Shred Client v%s", Version)

	cfg, err := transport.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	if err := validateConfig(cfg); err != nil {
		log.Fatalf("Invalid config: %v", err)
	}

	clientConfig := &engine.ClientConfig{
		TransportConfig: &transport.Config{
			ServerAddr: cfg.ServerAddr,
			Protocol:   cfg.Protocol,
		},
		AuthKey:        []byte(cfg.SecretKey),
		SwitchInterval: 5 * time.Minute,
		Modes: []shred.ProtocolMode{
			shred.ModeMinecraft,
			shred.ModeWebRTC,
			shred.ModeQUIC,
			shred.ModeRuTube,
		},
		HandshakeTimeout:       10 * time.Second,
		EnableReplayProtection: true,
	}

	client := engine.NewClient(clientConfig)

	client.SetOnPacket(func(data []byte) {
		log.Printf("Received packet from server: %d bytes", len(data))
	})

	if err := client.Start(); err != nil {
		log.Fatalf("Failed to start client: %v", err)
	}
	log.Println("Client connected to server")

	tunDev, err := tun.NewTunDevice()
	if err != nil {
		log.Fatalf("Failed to create TUN device: %v", err)
	}
	defer tunDev.Close()

	if err := tunDev.SetupIP(*tunAddr); err != nil {
		log.Printf("Warning: Failed to set IP: %v", err)
	}
	log.Printf("TUN device created, IP: %s", *tunAddr)

	go func() {
		for {
			data, err := tunDev.Read()
			if err != nil {
				log.Printf("TUN read error: %v", err)
				return
			}
			if err := client.Send(data); err != nil {
				log.Printf("Failed to send TUN packet: %v", err)
			}
		}
	}()

	client.SetOnPacket(func(data []byte) {
		if err := tunDev.Write(data); err != nil {
			log.Printf("Failed to write to TUN: %v", err)
		}
	})

	cmd := exec.Command("route", "add", "0.0.0.0", "mask", "0.0.0.0", "10.0.0.1", "metric", "1")
	if err := cmd.Run(); err != nil {
		log.Printf("Warning: Failed to add route automatically: %v", err)
		log.Println("Please run manually as administrator: route add 0.0.0.0 mask 0.0.0.0 10.0.0.1 metric 1")
	} else {
		log.Println("Default route added successfully")
		client.SetTunAdded(true)
	}

	log.Println("=========================================")
	log.Println("VPN is running!")
	log.Printf("TUN interface IP: %s", *tunAddr)
	log.Println("=========================================")

	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			stats := client.GetStats()
			log.Printf("Stats: mode=%s, sent=%d, recv=%d",
				stats["current_mode"], stats["packets_sent"], stats["packets_recv"])
		}
	}()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	sig := <-sigChan
	log.Printf("Received signal: %v, shutting down...", sig)

	stopChan := make(chan bool)
	go func() {
		client.Stop()
		stopChan <- true
	}()

	select {
	case <-stopChan:
		log.Println("Client stopped gracefully")
	case <-time.After(10 * time.Second):
		log.Println("Shutdown timeout, forcing exit")
	}
}

func validateConfig(cfg *transport.Config) error {
	if cfg.ServerAddr == "" {
		return flag.ErrHelp
	}
	if len(cfg.SecretKey) == 0 {
		return flag.ErrHelp
	}
	if cfg.Mode != "tcp" && cfg.Mode != "udp" && cfg.Mode != "dual" {
		return flag.ErrHelp
	}
	return nil
}
