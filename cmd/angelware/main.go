// Command angelware is a DemonWare replacement for WWE SmackDown vs. Raw 2007 (PS2).
//
// It serves the auth service and lobby service gateway on TCP 3074 and STUN/NAT
// discovery on UDP 3074 and 3075. DNS redirection of the game's demonware.net names
// to this host is handled elsewhere.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/princebyyourlogic/angelware/internal/auth"
	"github.com/princebyyourlogic/angelware/internal/lobby"
	"github.com/princebyyourlogic/angelware/internal/server"
	"github.com/princebyyourlogic/angelware/internal/session"
	"github.com/princebyyourlogic/angelware/internal/store"
	"github.com/princebyyourlogic/angelware/internal/stun"
)

type config struct {
	PublicIP    netip.Addr
	Bind        string
	Port        int
	STUNAltPort int
	DatabaseURL string
	AuthMode    auth.Mode
	LogLevel    slog.Level
}

func env(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return def
}

func loadConfig() (config, error) {
	c := config{Bind: env("ANGELWARE_BIND", "0.0.0.0"), DatabaseURL: os.Getenv("ANGELWARE_DATABASE_URL"),
		AuthMode: auth.Mode(env("ANGELWARE_AUTH_MODE", string(auth.Verify)))}
	var err error
	if c.PublicIP, err = netip.ParseAddr(os.Getenv("ANGELWARE_PUBLIC_IP")); err != nil || !c.PublicIP.Is4() {
		return c, errors.New("ANGELWARE_PUBLIC_IP must be the server's reachable IPv4 address")
	}
	if c.Port, err = strconv.Atoi(env("ANGELWARE_PORT", "3074")); err != nil {
		return c, fmt.Errorf("ANGELWARE_PORT: %w", err)
	}
	if c.STUNAltPort, err = strconv.Atoi(env("ANGELWARE_STUN_ALT_PORT", "3075")); err != nil {
		return c, fmt.Errorf("ANGELWARE_STUN_ALT_PORT: %w", err)
	}
	if c.AuthMode != auth.Verify && c.AuthMode != auth.Open {
		return c, fmt.Errorf("ANGELWARE_AUTH_MODE must be %q or %q", auth.Verify, auth.Open)
	}
	if err := c.LogLevel.UnmarshalText([]byte(env("ANGELWARE_LOG_LEVEL", "info"))); err != nil {
		return c, fmt.Errorf("ANGELWARE_LOG_LEVEL: %w", err)
	}
	return c, nil
}

func main() {
	cfg, err := loadConfig()
	if err != nil {
		fmt.Fprintln(os.Stderr, "angelware:", err)
		os.Exit(2)
	}
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: cfg.LogLevel}))
	if err := run(cfg, log); err != nil && !errors.Is(err, context.Canceled) {
		log.Error("exiting", "err", err)
		os.Exit(1)
	}
}

func run(cfg config, log *slog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var st store.Store = store.NewMemory()
	if cfg.DatabaseURL != "" {
		pg, err := store.OpenPostgres(ctx, cfg.DatabaseURL)
		if err != nil {
			return err
		}
		st = pg
	} else {
		log.Warn("ANGELWARE_DATABASE_URL not set: keeping data in memory only")
	}
	defer st.Close()

	sessions := session.NewRegistry()
	tcp := &server.TCP{
		Auth: &auth.Service{Store: st, Sessions: sessions, Mode: cfg.AuthMode, Log: log.With("svc", "auth")},
		Lobby: &lobby.Server{Store: st, Sessions: sessions, Log: log.With("svc", "lobby"),
			Matchmaking: lobby.NewMatchmaking(log.With("svc", "matchmaking"))},
		Log: log,
	}
	ln, err := net.Listen("tcp4", net.JoinHostPort(cfg.Bind, strconv.Itoa(cfg.Port)))
	if err != nil {
		return err
	}
	stunSrv := &stun.Server{PublicIP: cfg.PublicIP, Port: cfg.Port, AltPort: cfg.STUNAltPort,
		Log: log.With("svc", "stun")}

	errs := make(chan error, 2)
	go func() { errs <- tcp.Serve(ctx, ln) }()
	go func() { errs <- stunSrv.Run(ctx, cfg.Bind) }()
	log.Info("angelware listening", "bind", cfg.Bind, "tcp", cfg.Port, "udp", []int{cfg.Port, cfg.STUNAltPort},
		"public_ip", cfg.PublicIP.String(), "auth_mode", cfg.AuthMode, "postgres", cfg.DatabaseURL != "")
	err = <-errs
	stop()
	return err
}
