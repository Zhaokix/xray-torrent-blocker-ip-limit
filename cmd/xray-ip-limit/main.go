package main

import (
	"flag"
	"log/slog"
	"os"

	"xray-ip-limit/config"
	"xray-ip-limit/firewall"
	"xray-ip-limit/storage"
	"xray-ip-limit/watcher"
)

func main() {
	configPath := flag.String("config", "/opt/xray-ip-limit/config.yaml", "path to config file")
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	cfg, err := config.Load(*configPath)
	if err != nil {
		slog.Error("config load failed", "path", *configPath, "err", err)
		os.Exit(1)
	}

	if err := os.MkdirAll(cfg.StorageDir, 0755); err != nil {
		slog.Error("create storage dir failed", "err", err)
		os.Exit(1)
	}

	fw, err := firewall.NewManager(cfg.BanMode, cfg.DryRun)
	if err != nil {
		slog.Error("firewall init failed", "backend", cfg.BanMode, "err", err)
		os.Exit(1)
	}

	st, err := storage.New(cfg.StorageDir)
	if err != nil {
		slog.Error("storage init failed", "err", err)
		os.Exit(1)
	}

	w := watcher.New(cfg, st, fw)

	slog.Info("xray-ip-limit starting",
		"log_file", cfg.LogFile,
		"ip_limit", cfg.IPLimit,
		"window", cfg.Window,
		"ban_duration", cfg.BanDuration,
		"ban_mode", cfg.BanMode,
		"firewall_backend", fw.Name(),
		"dry_run", cfg.DryRun,
	)

	if err := w.Run(); err != nil {
		slog.Error("watcher failed", "err", err)
		os.Exit(1)
	}
}
