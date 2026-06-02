package main

import (
	"flag"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/sys/windows"

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
	if !isAdmin() {
		log.Println("Requesting administrator privileges...")
		if err := runAsAdmin(); err != nil {
			log.Fatalf("Failed to elevate: %v", err)
		}
		return
	}

	configPath := flag.String("config", "config_tcp.json", "config file path")
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
			shred.ModeVK,
			shred.ModeRuTube,
			shred.ModeYandex,
			shred.ModeOzon,
			shred.ModeWildberries,
			shred.ModeSberID,
			shred.ModeGosuslugi,
			shred.ModeWebRTC,
			shred.ModeQUIC,
			shred.ModeTLS,
		},
		HandshakeTimeout:       10 * time.Second,
		EnableReplayProtection: true,
		DNSServer:              cfg.DNSServer,
		DNSOverHTTPS:           cfg.DNSOverHTTPS,
		TLSSNI:                 cfg.TLSSNI,
		TLSCertFetch:           cfg.TLSCertFetch,
		FragmentEnabled:        cfg.FragmentEnabled,
		FragmentMin:            cfg.FragmentMin,
		FragmentMax:            cfg.FragmentMax,
		BackgroundEnabled:      true,
		BackgroundInterval:     30 * time.Second,
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

	tunName := tunDev.Name()

	// Устанавливаем TUN метрику 1 (приоритетный)
	exec.Command("netsh", "interface", "ipv4", "set", "interface", tunName, "metric=1").Run()
	log.Printf("Set TUN interface metric to 1")

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

	go func() {
		time.Sleep(2 * time.Second)
		exec.Command("route", "add", "0.0.0.0", "mask", "0.0.0.0", "10.0.0.1", "metric", "1").Run()
		log.Println("Default route added successfully")
	}()

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

	<-sigChan
	log.Println("Shutting down...")

	exec.Command("route", "delete", "0.0.0.0").Run()
	exec.Command("netsh", "interface", "ipv4", "set", "interface", tunName, "metric=auto").Run()

	client.Stop()
	log.Println("Client stopped")
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

func isAdmin() bool {
	_, err := os.Open(`\\.\PHYSICALDRIVE0`)
	return err == nil
}

func runAsAdmin() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	verb, _ := windows.UTF16PtrFromString("runas")
	file, _ := windows.UTF16PtrFromString(exe)
	return windows.ShellExecute(0, verb, file, nil, nil, 1)
}
