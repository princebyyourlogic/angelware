package stun

import (
	"testing"
	"time"
)

func TestObserverReceiptOnlyBindsCurrentDirectAttempt(t *testing.T) {
	n := newNetwork(t, Adaptive, []string{"EDM", "EDM"}, false)
	base := time.Now().Add(-200 * time.Millisecond)
	for _, c := range n.clients {
		c.lastSeen = base
	}
	n.pump(n.introduction(0, 1, base), base.Add(10*time.Millisecond), true)
	s := &Server{router: n.router, Log: discard}
	room := [8]byte{1}
	s.BeginObservation(room, n.clients[1].control, base.Add(-time.Second))
	s.ObserveConnectivity(room, n.clients[1].control, n.clients[0].control.Addr(), base.Add(-time.Second), base.Add(100*time.Millisecond), true)
	at := n.router.adaptive.attempts[pair{n.clients[0].id, n.clients[1].id}]
	if at == nil || !at.directReceipt {
		t.Fatal("current traversal did not receive the direct proof")
	}
	n.introduction(0, 1, base.Add(1200*time.Millisecond))
	if len(n.router.adaptive.offered) != 0 {
		t.Fatal("late duplicate offered relay after direct proof")
	}
	// A new signed traversal must not inherit a prior room/nonce's proof.
	req, _ := parse(append([]byte{10}, at.packet[1:]...))
	req.raw[3] ^= 1
	n.router.adaptive.introduce(req, n.clients[0].control, base.Add(1300*time.Millisecond))
	fresh := n.router.adaptive.attempts[pair{n.clients[0].id, n.clients[1].id}]
	if fresh == at || fresh.directReceipt {
		t.Fatal("new traversal inherited stale observer proof")
	}
}

func TestObserverNeverCallsAnAdmittedRelayDirect(t *testing.T) {
	n := newNetwork(t, Adaptive, []string{"EDM", "EDM"}, false)
	base := time.Now().Add(-1500 * time.Millisecond)
	for _, c := range n.clients {
		c.lastSeen = base
	}
	n.pump(n.introduction(0, 1, base), base.Add(10*time.Millisecond), true)
	n.pump(n.introduction(0, 1, base.Add(1100*time.Millisecond)), base.Add(1200*time.Millisecond), true)
	if len(n.router.adaptive.offered) != 1 {
		t.Fatal("test did not offer relay")
	}
	s := &Server{router: n.router, Log: discard}
	s.BeginObservation([8]byte{1}, n.clients[1].control, base.Add(-time.Second))
	s.ObserveConnectivity([8]byte{1}, n.clients[1].control, n.clients[0].control.Addr(), base.Add(-time.Second), base.Add(1300*time.Millisecond), true)
	for _, at := range n.router.adaptive.attempts {
		if at.directReceipt {
			t.Fatal("relayed or ambiguous mesh was called direct")
		}
	}
}

func TestObserverRejectsOldReceiptAndOldRoomForNewAttempt(t *testing.T) {
	n := newNetwork(t, Adaptive, []string{"EDM", "EDM"}, false)
	base := time.Now().Add(-200 * time.Millisecond)
	for _, c := range n.clients {
		c.lastSeen = base
	}
	n.introduction(0, 1, base)
	s := &Server{router: n.router, Log: discard}
	// This observer started after the traversal; it cannot suppress its retry.
	s.BeginObservation([8]byte{1}, n.clients[1].control, base.Add(50*time.Millisecond))
	s.ObserveConnectivity([8]byte{1}, n.clients[1].control, n.clients[0].control.Addr(), base.Add(50*time.Millisecond), base.Add(100*time.Millisecond), true)
	for _, at := range n.router.adaptive.attempts {
		if at.directReceipt {
			t.Fatal("different generation's receipt was attached")
		}
	}
	s.ObserveConnectivity([8]byte{1}, n.clients[1].control, n.clients[0].control.Addr(), base.Add(-time.Minute), base.Add(-10*time.Second), true)
	for _, at := range n.router.adaptive.attempts {
		if at.directReceipt {
			t.Fatal("expired receipt accepted")
		}
	}
}

func TestObserverAmbiguityDoesNotSuppressFallback(t *testing.T) {
	for _, extra := range []bool{false, true} {
		t.Run(map[bool]string{false: "multiple-key-recipients", true: "multiple-UDP-endpoints"}[extra], func(t *testing.T) {
			modes := []string{"EDM", "EDM"}
			if extra {
				modes = append(modes, "EDM")
			}
			n := newNetwork(t, Adaptive, modes, false)
			base := time.Now().Add(-200 * time.Millisecond)
			for _, c := range n.clients {
				c.lastSeen = base
			}
			n.pump(n.introduction(0, 1, base), base.Add(10*time.Millisecond), true)
			s := &Server{router: n.router, Log: discard}
			s.BeginObservation([8]byte{1}, n.clients[1].control, base.Add(-time.Second))
			s.ObserveConnectivity([8]byte{1}, n.clients[1].control, n.clients[0].control.Addr(), base.Add(-time.Second), base.Add(100*time.Millisecond), extra)
			for _, at := range n.router.adaptive.attempts {
				if at.directReceipt {
					t.Fatal("ambiguous report treated as direct")
				}
			}
			n.introduction(0, 1, base.Add(1200*time.Millisecond))
			if len(n.router.adaptive.offered) != 1 {
				t.Fatal("inconclusive report disabled native fallback")
			}
		})
	}
}

func TestNewRoomClearsThePriorRoomsDirectReceipt(t *testing.T) {
	n := newNetwork(t, Adaptive, []string{"EDM", "EDM"}, false)
	base := time.Now().Add(-200 * time.Millisecond)
	for _, c := range n.clients {
		c.lastSeen = base
	}
	n.introduction(0, 1, base)
	s := &Server{router: n.router, Log: discard}
	started := base.Add(-time.Second)
	s.BeginObservation([8]byte{1}, n.clients[1].control, started)
	s.ObserveConnectivity([8]byte{1}, n.clients[1].control, n.clients[0].control.Addr(), started, base.Add(100*time.Millisecond), true)
	at := n.router.adaptive.attempts[pair{n.clients[0].id, n.clients[1].id}]
	if !at.directReceipt {
		t.Fatal("initial proof missing")
	}
	s.BeginObservation([8]byte{2}, n.clients[1].control, base.Add(150*time.Millisecond))
	s.ObserveConnectivity([8]byte{1}, n.clients[1].control, n.clients[0].control.Addr(), started, base.Add(100*time.Millisecond), true)
	if at.directReceipt {
		t.Fatal("old room report restored a cleared proof")
	}
}
