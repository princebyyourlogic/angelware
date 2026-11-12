// Package server accepts TCP connections on the shared auth/gateway port.
//
// Both DemonWare hostnames (auth.mmp and lsg.mmp) point at one address and port, so
// each connection is classified by its first frame: the gateway opens with plain
// message 7, auth requests always use even message types.
package server

import (
	"bufio"
	"context"
	"errors"
	"log/slog"
	"net"
	"time"

	"github.com/princebyyourlogic/angelware/internal/auth"
	"github.com/princebyyourlogic/angelware/internal/frame"
	"github.com/princebyyourlogic/angelware/internal/lobby"
)

// firstFrameTimeout bounds how long an idle connection may sit before speaking.
const firstFrameTimeout = 30 * time.Second

type TCP struct {
	Auth  *auth.Service
	Lobby *lobby.Server
	Log   *slog.Logger
}

// Serve accepts connections until ctx ends.
func (s *TCP) Serve(ctx context.Context, ln net.Listener) error {
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if errors.Is(err, net.ErrClosed) {
				return err
			}
			s.Log.Warn("accept", "err", err)
			continue
		}
		go s.handle(ctx, c)
	}
}

func (s *TCP) handle(ctx context.Context, c net.Conn) {
	defer c.Close()
	if tc, ok := c.(*net.TCPConn); ok {
		tc.SetKeepAlive(true)
	}
	go func() {
		<-ctx.Done()
		c.Close()
	}()
	r := bufio.NewReader(c)
	c.SetReadDeadline(time.Now().Add(firstFrameTimeout))
	first, err := frame.Read(r)
	if err != nil {
		s.Log.Debug("connection closed before first frame", "peer", c.RemoteAddr().String(), "err", err)
		return
	}
	c.SetReadDeadline(time.Time{})
	if !first.Encrypted && first.Type == lobby.MsgHello {
		s.Lobby.Serve(ctx, c, r, first)
		return
	}
	s.Auth.Serve(ctx, c, r, first)
}
