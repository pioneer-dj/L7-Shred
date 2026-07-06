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
	// UAC теперь обрабатывается через манифест Windows
	// Проверка isAdmin() и runAsAdmin() больше не нужны

	configPath := flag.String("config", "config_udp.json", "config file path")
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

	log.Printf("[DEBUG] SplitTunnel: %v", cfg.SplitTunnel)
	log.Printf("[DEBUG] ReliableUDP: %v", cfg.ReliableUDP)

	var modes []shred.ProtocolMode
	if len(cfg.Modes) > 0 {
		for _, m := range cfg.Modes {
			switch m {
			case "vk":
				modes = append(modes, shred.ModeVK)
			case "rutube":
				modes = append(modes, shred.ModeRuTube)
			case "yandex":
				modes = append(modes, shred.ModeYandex)
			case "ozon":
				modes = append(modes, shred.ModeOzon)
			case "wildberries":
				modes = append(modes, shred.ModeWildberries)
			case "sberid":
				modes = append(modes, shred.ModeSberID)
			case "gosuslugi":
				modes = append(modes, shred.ModeGosuslugi)
			case "webrtc":
				modes = append(modes, shred.ModeWebRTC)
			case "quic":
				modes = append(modes, shred.ModeQUIC)
			case "tls":
				modes = append(modes, shred.ModeTLS)
			default:
				log.Printf("Unknown mode %s, using VK", m)
				modes = append(modes, shred.ModeVK)
			}
		}
	} else {
		modes = []shred.ProtocolMode{
			shred.ModeVK, shred.ModeRuTube, shred.ModeYandex,
			shred.ModeOzon, shred.ModeWildberries, shred.ModeSberID,
			shred.ModeGosuslugi, shred.ModeWebRTC, shred.ModeQUIC, shred.ModeTLS,
		}
	}

	switchInterval := 5 * time.Minute
	if cfg.SwitchInterval > 0 {
		switchInterval = time.Duration(cfg.SwitchInterval) * time.Second
	}

	clientConfig := &engine.ClientConfig{
		TransportConfig: &transport.Config{
			ServerAddr:      cfg.ServerAddr,
			Protocol:        "udp",
			ReliableUDP:     cfg.ReliableUDP,
			SecretKey:       cfg.SecretKey,
			MTU:             cfg.MTU,
			Cipher:          cfg.Cipher,
			DNSServer:       cfg.DNSServer,
			DNSOverHTTPS:    cfg.DNSOverHTTPS,
			TLSSNI:          cfg.TLSSNI,
			TLSCertFetch:    cfg.TLSCertFetch,
			FragmentEnabled: cfg.FragmentEnabled,
			FragmentMin:     cfg.FragmentMin,
			FragmentMax:     cfg.FragmentMax,
		},
		AuthKey:                []byte(cfg.SecretKey),
		Cipher:                 cfg.Cipher,
		SwitchInterval:         switchInterval,
		Modes:                  modes,
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
		ReliableUDP:            cfg.ReliableUDP,
		SplitTunnel:            cfg.SplitTunnel,
		TUNInterface:           "l7shred",
	}

	client := engine.NewClient(clientConfig)

	log.Println("Creating TUN device...")
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
	log.Printf("TUN interface name: %s", tunName)

	cmd := exec.Command("netsh", "interface", "ipv4", "set", "interface", tunName, "metric=1")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	cmd.Run()

	if err := client.Start(); err != nil {
		log.Fatalf("Failed to start client: %v", err)
	}
	log.Println("Client connected to server")

	go func() {
		for {
			data, err := tunDev.Read()
			if err != nil {
				log.Printf("TUN read error: %v", err)
				return
			}
			if len(data) == 0 {
				continue
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
		for {
			time.Sleep(30 * time.Second)
			stats := client.GetStats()
			log.Printf("Stats: mode=%s, sent=%d, recv=%d",
				stats["current_mode"], stats["packets_sent"], stats["packets_recv"])
		}
	}()

	log.Println("=========================================")
	log.Println("VPN is running!")
	log.Printf("TUN interface IP: %s", *tunAddr)
	log.Println("=========================================")

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	<-sigChan
	log.Println("Shutting down...")

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
	return nil
}