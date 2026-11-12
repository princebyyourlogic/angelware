package store

import (
	"context"
	"errors"
	"os"
	"testing"
)

// Runs against a real database when ANGELWARE_TEST_DATABASE_URL is set, e.g.
// postgres://angelware:test@localhost:55499/angelware?sslmode=disable
func TestPostgres(t *testing.T) {
	url := os.Getenv("ANGELWARE_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("ANGELWARE_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	p, err := OpenPostgres(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	// Schema is idempotent: opening twice must work.
	if p2, err := OpenPostgres(ctx, url); err != nil {
		t.Fatal(err)
	} else {
		p2.Close()
	}

	var id uint64 = 0xfd48752c82ac6ca9 // high bit set: stored as negative bigint
	p.pool.Exec(ctx, `DELETE FROM accounts WHERE user_id = $1`, int64(id))
	p.DeleteProfile(ctx, id)

	acct := Account{UserID: id, Name: "pgtest", PasswordTiger: make([]byte, 24)}
	if err := p.CreateAccount(ctx, acct); err != nil {
		t.Fatal(err)
	}
	if err := p.CreateAccount(ctx, acct); !errors.Is(err, ErrExists) {
		t.Fatalf("duplicate account: %v", err)
	}
	if got, err := p.Account(ctx, id); err != nil || got.Name != "pgtest" {
		t.Fatalf("account %+v %v", got, err)
	}
	if _, err := p.Account(ctx, 1); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing account: %v", err)
	}

	if _, err := p.PrivateProfile(ctx, id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing private profile: %v", err)
	}
	if err := p.SetPublicProfile(ctx, id, PublicProfile{A: 1, B: -2, Data: []byte{9}}); err != nil {
		t.Fatal(err)
	}
	if err := p.SetPrivateProfile(ctx, id, PrivateProfile{1, 0, 0, 3}); err != nil {
		t.Fatal(err)
	}
	if pp, err := p.PrivateProfile(ctx, id); err != nil || pp != (PrivateProfile{1, 0, 0, 3}) {
		t.Fatalf("private %v %v", pp, err)
	}
	if pub, err := p.PublicProfile(ctx, id); err != nil || pub.B != -2 || pub.Data[0] != 9 {
		t.Fatalf("public %+v %v", pub, err)
	}
	for i := 0; i < 2; i++ {
		if err := p.WriteStats(ctx, id, StatsRow{Board: 3, Rating: int64(i), Values: []int32{1, 2}}); err != nil {
			t.Fatal(err)
		}
	}
}
