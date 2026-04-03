package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/l7-shred/core/internal/engine"
	"github.com/l7-shred/core/internal/transport"
)

var (
	Version   = "dev"
	BuildTime = "unknown"
)

func main() {
	configPath := flag.String("config", "configs/server.standalone.json", "config file path")
	version := flag.Bool("version", false, "show version")
	flag.Parse()

	if *version {
		log.Printf("L7-Shred Server v%s (built %s)", Version, BuildTime)
		return
	}

	log.Printf("Starting L7-Shred Server v%s", Version)

	cfg, err := transport.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	if err := validateConfig(cfg); err != nil {
		log.Fatalf("Invalid config: %v", err)
	}

	server := engine.NewServer(cfg)

	if err := server.Start(); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
	log.Printf("Server listening on %s (mode: %s)", cfg.ListenAddr, cfg.Mode)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	sig := <-sigChan
	log.Printf("Received signal: %v, shutting down...", sig)

	stopChan := make(chan bool)
	go func() {
		server.Stop()
		stopChan <- true
	}()

	select {
	case <-stopChan:
		log.Println("Server stopped gracefully")
	case <-time.After(10 * time.Second):
		log.Println("Shutdown timeout, forcing exit")
	}
}

func validateConfig(cfg *transport.Config) error {
	if cfg.ListenAddr == "" {
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
