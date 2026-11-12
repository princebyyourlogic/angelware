package lobby

import (
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"testing"

	"github.com/princebyyourlogic/angelware/internal/bitbuf"
)

type observerGateway struct{ ip string }

func (g *observerGateway) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP(g.ip), Port: 40000}
}

func observerRoom(t *testing.T) (*Matchmaking, *observerGateway, []bitbuf.Field, *[]ConnectivityEvent) {
	t.Helper()
	host := &observerGateway{"198.51.100.1"}
	info := hostedSession(nil)
	copy(info[0].Bytes[18:22], net.ParseIP(host.ip).To4())
	binary.LittleEndian.PutUint16(info[0].Bytes[22:24], 3074)
	m := NewMatchmaking(slog.New(slog.NewTextHandler(io.Discard, nil)))
	var events []ConnectivityEvent
	m.ObserveConnectivity = func(e ConnectivityEvent) { events = append(events, e) }
	m.create(host, Task{ID: mmCreate}, info)
	if len(events) != 1 || !events[0].Created {
		t.Fatal("fresh eligible room was not observed")
	}
	return m, host, info, &events
}

func updatedPeers(info []bitbuf.Field, n uint64) []bitbuf.Field {
	out := append([]bitbuf.Field(nil), info...)
	out[slotPublicUsed] = bitbuf.Int(bitbuf.I32, n)
	return out
}

func TestNativeCompletionRequiresRoomOwnerAndCountTransition(t *testing.T) {
	m, host, info, events := observerRoom(t)
	guest := &observerGateway{"198.51.100.2"}
	if len(m.search(guest, searchQuery{maxResults: 20})) != 1 {
		t.Fatal("room missing")
	}
	m.update(guest, updatedPeers(info, 2))
	if len(*events) != 1 {
		t.Fatal("non-owner forged a completion report")
	}
	m.update(host, updatedPeers(info, 1))
	m.update(host, updatedPeers(info, 2))
	m.update(host, updatedPeers(info, 2))
	if len(*events) != 2 {
		t.Fatal("completion absent or repeated without a new count transition")
	}
	e := (*events)[1]
	if !e.UniqueGuest || e.GuestIP.String() != guest.ip || e.Host.String() != "198.51.100.1:3074" || e.Created {
		t.Fatal("completion is not bound to the fresh room and guest")
	}
	if m.sessions[e.Room].info[slotPublicUsed].Int != 2 || len(m.search(guest, searchQuery{maxResults: 20})) != 0 {
		t.Fatal("observer altered slots or exposed a full room")
	}
}

func TestMultipleRoomKeyRecipientsRemainAmbiguous(t *testing.T) {
	m, host, info, events := observerRoom(t)
	m.search(&observerGateway{"198.51.100.2"}, searchQuery{maxResults: 20})
	m.search(&observerGateway{"198.51.100.3"}, searchQuery{maxResults: 20})
	m.update(host, updatedPeers(info, 2))
	if len(*events) != 2 || (*events)[1].UniqueGuest {
		t.Fatal("occupancy attributed to one of multiple key recipients")
	}
}

func TestObserverRejectsMalformedCountsAndSpoofedHost(t *testing.T) {
	m, host, info, events := observerRoom(t)
	m.search(&observerGateway{"198.51.100.2"}, searchQuery{maxResults: 20})
	bad := updatedPeers(info, 3)
	m.update(host, bad)
	if len(*events) != 1 {
		t.Fatal("invalid two-player count reported completion")
	}
	m.update(host, updatedPeers(info, 1))
	spoof := updatedPeers(info, 2)
	spoof[0] = bitbuf.Bytes(bitbuf.Blob, append([]byte(nil), info[0].Bytes...))
	spoof[0].Bytes[18] ^= 1
	m.update(host, spoof)
	if len(*events) != 1 {
		t.Fatal("changed or spoofed host endpoint accepted")
	}
}

func TestFindByIDTracksTheInviteKeyRecipient(t *testing.T) {
	m, host, info, events := observerRoom(t)
	guest := &observerGateway{"198.51.100.2"}
	w := bitbuf.NewWriter(true).U8(0).Field(bitbuf.Bytes(bitbuf.Blob, info[infoID].Bytes))
	r, err := bitbuf.NewReader(w.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	m.Handle(guest, Task{ID: mmFindByID, Args: r})
	m.update(host, updatedPeers(info, 2))
	if len(*events) != 2 || !(*events)[1].UniqueGuest || (*events)[1].GuestIP.String() != guest.ip {
		t.Fatal("find-by-ID/invite key recipient was not tracked")
	}
}
