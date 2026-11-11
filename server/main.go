// Package main implements the Veil relay.
//
// The relay is a switchboard, not a participant. It routes opaque blobs and
// keeps an outbox for peers that are offline. It holds no key material, so it
// has no code path that could read anything it forwards.
package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	var (
		addr   = flag.String("addr", envOr("VEIL_ADDR", ":8080"), "listen address")
		dbPath = flag.String("db", envOr("VEIL_DB", "veil.db"), "sqlite database path")
	)
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	st, err := OpenStore(*dbPath)
	if err != nil {
		logger.Error("open store", "path", *dbPath, "err", err)
		os.Exit(1)
	}
	defer st.Close()

	hub := NewHub(st, logger)

	srv := &http.Server{
		Addr:              *addr,
		Handler:           newMux(hub),
		ReadHeaderTimeout: 10 * time.Second,
		// A websocket connection is long lived, so no write timeout here:
		// the per-connection ping/pong deadlines govern liveness instead.
		IdleTimeout: 120 * time.Second,
	}

	go func() {
		logger.Info("veil relay listening", "addr", *addr, "db", *dbPath)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("listen", "err", err)
			os.Exit(1)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop

	logger.Info("shutting down")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
