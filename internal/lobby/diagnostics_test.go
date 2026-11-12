package lobby

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/princebyyourlogic/angelware/internal/bitbuf"
	"github.com/princebyyourlogic/angelware/internal/dwcrypto"
	"github.com/princebyyourlogic/angelware/internal/frame"
	"github.com/princebyyourlogic/angelware/internal/session"
	"github.com/princebyyourlogic/angelware/internal/store"
)

type diagnosticLog struct{ records chan map[string]any }

func (d diagnosticLog) Write(b []byte) (int, error) {
	var record map[string]any
	if err := json.Unmarshal(b, &record); err != nil {
		return 0, err
	}
	d.records <- record
	return len(b), nil
}

func TestTaskTimingCorrelatesTheWrittenReplyAndQueueDelay(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	sink := diagnosticLog{make(chan map[string]any, 20)}
	c := &Conn{srv: &Server{Store: store.NewMemory()}, conn: server,
		log:  slog.New(slog.NewJSONHandler(sink, &slog.HandlerOptions{Level: slog.LevelDebug})),
		sess: session.Session{UserID: 42, Key: bytes.Repeat([]byte{1}, 24)},
		out:  make(chan outbound, outQueue), done: make(chan struct{})}
	for seq := range 2 {
		payload := bitbuf.NewWriter(true).U8(4).U8(uint8(seq)).U8(profReadPrivate).U8(0).Bytes()
		body := binary.LittleEndian.AppendUint32(nil, frame.Magic)
		body = append(body, svcProfiles)
		body = append(body, payload...)
		body = append(body, make([]byte, (8-len(body)%8)%8)...)
		ciphertext, err := dwcrypto.Encrypt(c.sess.Key, dwcrypto.SeedIV(123), body)
		if err != nil {
			t.Fatal(err)
		}
		if err := c.handle(context.Background(), frame.Frame{Encrypted: true, Seed: 123, Payload: ciphertext}); err != nil {
			t.Fatal(err)
		}
	}
	// Delay the writer to create a real outbound queue wait, independent of the
	// profile task itself. The trace must distinguish these two durations.
	time.Sleep(15 * time.Millisecond)
	finished := make(chan struct{})
	go func() { c.writer(); close(finished) }()
	defer func() {
		close(c.done)
		server.Close()
		client.Close()
		<-finished
	}()
	client.SetReadDeadline(time.Now().Add(time.Second))
	r := bufio.NewReader(client)
	for seq := range 2 {
		reply, err := frame.Read(r)
		if err != nil || reply.Type != msgTaskReply {
			t.Fatalf("reply: %v", err)
		}
		payload, _ := bitbuf.NewReader(reply.Payload)
		slot, _ := payload.U8()
		gotSeq, _ := payload.U8()
		if slot != 4 || gotSeq != uint8(seq) {
			t.Fatal("diagnostics changed reply correlation")
		}
	}
	seen := map[float64]bool{}
	for len(seen) < 2 {
		select {
		case record := <-sink.records:
			if record["msg"] != "gateway frame sent" {
				continue
			}
			if record["service"] != float64(svcProfiles) || record["task"] != float64(profReadPrivate) ||
				record["slot"] != float64(4) || record["queue_ms"].(float64) < 5 || record["write_ms"].(float64) < 0 {
				t.Fatalf("missing correlation or queue/write timing: %v", record)
			}
			seen[record["seq"].(float64)] = true
		case <-time.After(time.Second):
			t.Fatal("missing written-reply trace")
		}
	}
}
