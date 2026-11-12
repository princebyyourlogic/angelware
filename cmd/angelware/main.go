// Command angelware is a DemonWare replacement for PS2 titles.
//
// For WWE SmackDown vs. Raw 2007 it serves the auth service and lobby service
// gateway on TCP 3074 and STUN/NAT on UDP 3074 and 3075. For Call of Duty 2: Big
// Red One (matchmaking via GameSpy elsewhere) it serves STUN/NAT on UDP 2273 and
// 2274, by default with peer traffic relayed through UDP 20000-20199. DNS
// redirection of the games' hostnames to this host is handled elsewhere.
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
	"strings"
	"syscall"
	"time"

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
	STUN        []stunTitle
}

type stunTitle struct {
	name string
	stun.Config
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
	return c, c.loadSTUN()
}

// loadSTUN configures one STUN service per title; they share the public IP and
// the relay port range.
func (c *config) loadSTUN() error {
	shared := stun.Config{PublicIP: c.PublicIP}
	var err error
	if shared.RelayLo, shared.RelayHi, err = portRange(env("ANGELWARE_RELAY_PORTS", "20000-20199")); err != nil {
		return fmt.Errorf("ANGELWARE_RELAY_PORTS: %w", err)
	}
	if shared.RelayMaxClients, err = strconv.Atoi(env("ANGELWARE_RELAY_MAX_CLIENTS", "64")); err != nil {
		return fmt.Errorf("ANGELWARE_RELAY_MAX_CLIENTS: %w", err)
	}
	window, err := strconv.ParseFloat(env("ANGELWARE_DIRECT_WINDOW", "1.0"), 64)
	if err != nil {
		return fmt.Errorf("ANGELWARE_DIRECT_WINDOW: %w", err)
	}
	shared.DirectWindow = time.Duration(window * float64(time.Second))

	svr := shared
	svr.Port, svr.AltPort = c.Port, c.STUNAltPort
	svr.Mode = stun.Mode(env("ANGELWARE_STUN_MODE", string(stun.Direct)))
	c.STUN = append(c.STUN, stunTitle{"svr2007", svr})

	if env("ANGELWARE_BRO", "on") != "off" {
		bro := shared
		bro.Mode = stun.Mode(env("ANGELWARE_BRO_MODE", string(stun.Relay)))
		if bro.Port, err = strconv.Atoi(env("ANGELWARE_BRO_PORT", "2273")); err != nil {
			return fmt.Errorf("ANGELWARE_BRO_PORT: %w", err)
		}
		if bro.AltPort, err = strconv.Atoi(env("ANGELWARE_BRO_ALT_PORT", "2274")); err != nil {
			return fmt.Errorf("ANGELWARE_BRO_ALT_PORT: %w", err)
		}
		c.STUN = append(c.STUN, stunTitle{"cod-bro", bro})
	}
	for _, t := range c.STUN {
		if err := t.Validate(); err != nil {
			return fmt.Errorf("%s stun: %w", t.name, err)
		}
	}
	return nil
}

func portRange(s string) (lo, hi int, err error) {
	a, b, ok := strings.Cut(s, "-")
	if !ok {
		return 0, 0, errors.New("want LOW-HIGH")
	}
	if lo, err = strconv.Atoi(a); err == nil {
		hi, err = strconv.Atoi(b)
	}
	return lo, hi, err
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
	errs := make(chan error, 1+len(cfg.STUN))
	go func() { errs <- tcp.Serve(ctx, ln) }()
	for _, t := range cfg.STUN {
		srv := &stun.Server{Config: t.Config, Bind: cfg.Bind, Log: log.With("svc", "stun", "title", t.name)}
		go func() { errs <- srv.Run(ctx) }()
	}
	log.Info("angelware listening", "bind", cfg.Bind, "tcp", cfg.Port, "public_ip", cfg.PublicIP.String(),
		"auth_mode", cfg.AuthMode, "postgres", cfg.DatabaseURL != "")
	err = <-errs
	stop()
	return err
}
