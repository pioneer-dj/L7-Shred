package main

import (
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/l7-shred/core/internal/api"
	"github.com/l7-shred/core/internal/auth"
	"github.com/l7-shred/core/internal/database"
	"github.com/l7-shred/core/internal/email"
	"github.com/l7-shred/core/internal/engine"
	"github.com/l7-shred/core/internal/payment"
	"github.com/l7-shred/core/internal/transport"
)

var (
	Version   = "dev"
	BuildTime = "unknown"
)

func main() {
	configPath := flag.String("config", "configs/server.kcp.json", "config file path")
	version := flag.Bool("version", false, "show version")
	flag.Parse()

	if *version {
		log.Printf("L7-Shred Server v%s (built %s)", Version, BuildTime)
		return
	}

	log.Printf("Starting L7-Shred Server v%s", Version)

	if err := database.InitDB(database.Config{
		Host:     "localhost",
		Port:     "5432",
		User:     "l7shred_user",
		Password: "auifgeuhoa_38phg",
		DBName:   "l7shred",
		SSLMode:  "disable",
	}); err != nil {
		log.Fatalf("Failed to init database: %v", err)
	}

	if err := database.AutoMigrate(database.GetDB()); err != nil {
		log.Fatalf("Failed to migrate database: %v", err)
	}

	auth.InitJWT("your-super-secret-jwt-key-change-me-in-production")

	api.InitSMTP(email.SMTPConfig{
		Host:     "smtp.ethereal.email",
		Port:     "587",
		Username: "isaac43@ethereal.email",
		Password: "Dj89V8xTZg8TE1UZ5y",
		From:     "isaac43@ethereal.email",
	})

	cfg, err := transport.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	if err := validateConfig(cfg); err != nil {
		log.Fatalf("Invalid config: %v", err)
	}

	router := api.SetupRoutes()

	router.HandleFunc("/api/payment/create-invoice", payment.CreateInvoiceHandler).Methods("POST")
	router.HandleFunc("/api/payment/webhook", payment.HandleWebhook).Methods("POST")
	router.HandleFunc("/api/payment/status", payment.GetSubscriptionStatus).Methods("GET")

	go func() {
		log.Printf("API server listening on :8444")
		if err := http.ListenAndServe(":8444", router); err != nil {
			log.Printf("API server error: %v", err)
		}
	}()

	server := engine.NewServer(cfg)

	if err := server.Start(); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
	log.Printf("VPN server listening on %s (mode: %s)", cfg.ListenAddr, cfg.Mode)

	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			stats := server.GetStats()
			log.Printf("Stats: connections=%d", stats["active_connections"])
		}
	}()

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