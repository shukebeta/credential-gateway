package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"credential-gateway/internal/config"
	"credential-gateway/internal/gateway"
)

func main() {
	configPath := flag.String("config", "", "path to config file (default: search standard locations)")
	flag.Parse()

	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Error("failed to load config", "err", err)
		os.Exit(1)
	}

	gw := gateway.New(cfg, log)
	if err := gw.Start(); err != nil {
		log.Error("failed to start gateway", "err", err)
		os.Exit(1)
	}

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Info("shutting down")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	gw.Stop(ctx)
	log.Info("stopped")
}
