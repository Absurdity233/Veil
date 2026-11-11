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
	"fmt"
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
		// Comma-separated list of origins a browser client may connect from.
		// Empty means native clients only, which is the safe default: the
		// Android app sends no Origin header at all.
		origins = flag.String("allowed-origins",
			envOr("VEIL_ALLOWED_ORIGINS", ""),
			"comma-separated browser origins allowed to open a websocket")
		// Container healthcheck mode.
		//
		// The runtime image is distroless: no shell, no curl, no wget. A
		// Docker HEALTHCHECK therefore has to be a binary call, and the only
		// binary guaranteed to exist in that image is this one.
		probe = flag.Bool("healthcheck", false,
			"probe a running relay's /health endpoint and exit")
		probeURL = flag.String("healthcheck-url",
			envOr("VEIL_HEALTH_URL", "http://127.0.0.1:8080/health"),
			"URL the -healthcheck probe requests")
	)
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	if *probe {
		os.Exit(runProbe(*probeURL))
	}

	st, err := OpenStore(*dbPath)
	if err != nil {
		logger.Error("open store", "path", *dbPath, "err", err)
		os.Exit(1)
	}
	defer st.Close()

	hub := NewHubWithOrigins(st, logger, *origins)

	srv := &http.Server{
		Addr:              *addr,
		Handler:           newMux(hub),
		ReadHeaderTimeout: 10 * time.Second,
		// A websocket connection is long lived, so no write timeout here:
		// the per-connection ping/pong deadlines govern liveness instead.
		IdleTimeout: 120 * time.Second,
	}

	// Periodic outbox sweep: expiry and the per-recipient ceiling.
	sweepCtx, stopSweep := context.WithCancel(context.Background())
	defer stopSweep()
	go func() {
		ticker := time.NewTicker(15 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-sweepCtx.Done():
				return
			case now := <-ticker.C:
				expired, trimmed, err := st.Sweep(now)
				if err != nil {
					logger.Warn("outbox sweep failed", "err", err)
					continue
				}
				if expired > 0 || trimmed > 0 {
					logger.Info("outbox swept", "expired", expired, "trimmed", trimmed)
				}
			}
		}
	}()

	certFile := envOr("VEIL_TLS_CERT", "")
	keyFile := envOr("VEIL_TLS_KEY", "")
	if (certFile == "") != (keyFile == "") {
		logger.Error("VEIL_TLS_CERT and VEIL_TLS_KEY must be set together")
		os.Exit(1)
	}
	tlsEnabled := certFile != "" && keyFile != ""

	go func() {
		if tlsEnabled {
			logger.Info("veil relay listening", "addr", *addr, "db", *dbPath, "tls", true)
			if err := srv.ListenAndServeTLS(certFile, keyFile); err != nil &&
				!errors.Is(err, http.ErrServerClosed) {
				logger.Error("listen", "err", err)
				os.Exit(1)
			}
			return
		}
		// Plain ws:// is only correct behind a TLS terminator. Saying so at
		// startup is cheaper than reading it in a README nobody opens.
		logger.Warn("serving plain ws://: TLS must be terminated in front of this process",
			"addr", *addr, "db", *dbPath, "tls", false)
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

	// Order matters. The hub goes first: it closes hijacked websockets with a
	// "going away" status, which http.Server.Shutdown does not touch. Without
	// it the process sat for 10 seconds and then died, and clients only found
	// out when their next write failed.
	hub.Shutdown(ctx)
	_ = srv.Shutdown(ctx)

	// Drain the store last, after no handler can be writing to it.
	expired, trimmed, err := st.Sweep(time.Now())
	if err != nil {
		logger.Warn("final sweep failed", "err", err)
	} else if expired > 0 || trimmed > 0 {
		logger.Info("final sweep", "expired", expired, "trimmed", trimmed)
	}
	logger.Info("relay stopped")
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// runProbe is the container healthcheck. Exit 0 means healthy.
//
// The image has nothing but the relay binary in it, so `-healthcheck` is how
// Docker asks "are you alive?" without a shell in the way. A plain TCP connect
// would not be enough: it says the port is bound, not that the store is
// usable, and the store is what actually breaks.
func runProbe(rawURL string) int {
	client := http.Client{Timeout: 5 * time.Second}

	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "healthcheck: bad url %q: %v\n", rawURL, err)
		return 1
	}

	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "healthcheck: %v\n", err)
		return 1
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "healthcheck: %s returned %d\n", rawURL, resp.StatusCode)
		return 1
	}
	return 0
}
