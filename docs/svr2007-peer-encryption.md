# SvR 2007 console-to-console encryption

Tested offline on 2026-11-12 against a captured connection between two retail US
v1.01 clients running in PCSX2. Both clients' private keys were recovered from
captured login randomness and independently matched their handshake public keys.
All **402 encrypted DemonWare peer packets** verified and decrypted: **201 in each
direction**. No emulator memory, saved private keys, or account passwords were used.

This covers DemonWare's `bdDTLS` peer channel. SvR's separate match transport must
be examined separately; it does not follow that every match packet uses this cipher.

## Private key generation and lifetime

All addresses below are offsets in the extracted `LBYM` overlay, loaded at base 0.

- `bdNetImpl::start` (`0x599f8`) creates its key object at object offset `+0x40`
  if it does not already exist, calling `bdDHKey::create` (`0x7ba28`). A new room
  does not necessarily create a new private key.
- `bdDHKey::create` requests 128 bytes through the `bdRandom` wrapper (`0x84610`).
  Its byte generator (`0xaddd8`) maintains a global Park–Miller state, initially
  seeded from the CPU Count/timer routine (`0x3e500`):

  ```text
  state = (16807 * state) mod 2147483647
  output_byte = state & 255
  ```

- These 128 bytes seed LibTomCrypt Yarrow: initial zeroed 32-byte pool,
  SHA256(pool || entropy), then AES-256 CTR with a little-endian counter, using
  the hash as the key and its first 16 bytes as the initial counter. The first
  28 output bytes become the big-endian private scalar on **secp224r1**.
- The corresponding public point is exchanged in a padded 100-byte LibTomCrypt
  DER public-key blob during `COOKIE_ECHO` / `COOKIE_ACK`.

The recreated Yarrow output also matched the installed LibTomCrypt implementation
for a fixed 128-byte input. The captured public-key matches validate the full
retail generation path, including curve and byte order.

## Why the captured key recovery works

Auth requests expose a 32-bit IV seed made from four consecutive output bytes of
the same generator. It is in an untyped, LSB-first bit buffer, after the leading
type-mode bit; do not treat the payload's first four bytes as byte-aligned seed data.

For an observed first byte, only about 2^23 possible internal states remain.
Checking the other three bytes quickly reduces this to a few candidates. The
generator is invertible, so candidates can be rewound to earlier output bytes.
Hashing the recovered 128-byte entropy window and regenerating the public key
gives an exact check against the captured handshake.

In this test both private-key entropy windows ended **32 generator bytes before
the login IV seed**. The checker searched offsets, rather than assuming 32.
The successful rerun tested 66 private-key candidates and finished in about
0.2 seconds on the development host, including compilation of the state checker.
Timing and the offset are observations from this capture, not guarantees for all runs.

Earlier server logs also contained three signup/login pairs whose consecutive
public IV seeds uniquely identified a shared generator stream.

## Traffic key and packet format

AngelWare generates a fresh 16-byte room key on room creation and returns it via
matchmaking. The current server sends matchmaking replies as plain gateway frames,
so this key can be extracted from the same capture.

At `0x367c0`, each console derives:

```text
shared_secret = ECDH(local_private, remote_public)  // 28 bytes
traffic_key   = Tiger192(shared_secret || room_key) // 24 bytes
```

Both recovered private keys independently produced the same shared secret.

`bdDTLSData` serialization (`0x37558`) and verification/decryption (`0x37c20`):

```text
u8 type = 6
u8 version = 2
u16 LE verification tag
u16 LE sequence number
8-byte HMAC tag
u16 LE encrypted plaintext length
3DES-CBC ciphertext, length rounded up to a multiple of 8
optional clear tail
```

The IV is the first 8 bytes of Tiger192 of the reconstructed 32-bit sequence
number's little-endian encoding. Padding bytes written by the sender are `0x01`.
The HMAC is HMAC-SHA1 with the same 24-byte traffic key, truncated to 8 bytes,
covering the first six header bytes followed by the ciphertext and clear tail.
It skips the HMAC field and the two-byte length field.

## Reproduce against your local capture

Dependencies: Python 3, `cryptography` with `hazmat.decrepit`, libgcrypt, and a C
compiler (`cc`). No server connections are made by the analysis tools.

```sh
python3 tools/svr_recover.py work/svr-rng-test.pcap
```

The helper C library is compiled into a temporary directory. Default rewind
search: 4096 bytes; override with `--max-rewind`. The reader supports classic
pcap with Ethernet, Linux cooked v1/v2, or raw IPv4, and complete TCP streams.
Capture before login and include the peer handshake and room-creation reply.
PCAPNG, fragmented IPv4, and captures beginning mid-frame are not supported.

Outputs in `work/svr-key-recovery/` (ignored by git):

- `report.json`: counts, matches, and verification results; no private keys.
- `recovered-keys.json`: recovered private/traffic key material, mode 0600.
- `decrypted-peer.jsonl`: decrypted payloads, mode 0600.

The captured two-client test authenticated and decrypted 402/402 packets.
An altered ciphertext must fail HMAC verification; public-key matching alone
is not the final acceptance criterion.

## Relay failure and host-address rewriting

The earlier attempt (`c4585b9`, reverted by `7de40c6`) changed the host's first
local address in matchmaking search results. After joining, the host sent its
own session data to the joiner, replacing that change. The game-side receive
handler is `LBYM 0x17f30`; it parses session data and calls the session update
path at `0xd9e8`.

`OMEN 0x3158` prepares the separate match transport. It starts with the host's
public IP/port, compares the local peer's public **IP string** with the host's,
and selects the host's first local IP/port when those strings match. Ports are
not part of that comparison. In always-relay mode every public address is the
relay server's IP, so all pairs select the local-address branch. PCSX2 sockets
mode commonly puts `192.0.2.100:3074` there, which does not reach the relay.

The joiner uses its own first local port as the match bind port. The host uses
its own first local port too. `OMEN 0x30e8` passes the prepared target and bind
port to `CGssSmack` / `CGssCtrl`. Rewriting only the host-sent copy preserves
those consoles' own local socket ports.

### Captured address-bearing message

The decoded DATA message **0x4f** (join accept) contains two host records: the
generic session record and the game-specific session data. Both carry a
25-byte `bdCommonAddr`:

```text
bytes  0..5   first local IPv4 + u16 LE port
bytes  6..17  two additional local endpoints
bytes 18..23  public IPv4 + u16 LE port
byte  24      NAT type
```

In this capture the address copies start at **bits 145 and 1177 inside the
message's bit buffer**. Those positions depend on the preceding host name and
record layout; the implementation finds matching host-record prefixes instead
of hard-coding them. It also requires the embedded room ID and room key to match
the handshake's room before editing the data.

The offline prototype changed both copies from local `192.0.2.100:3074` / public
`192.168.2.141:47908` to local and public `192.168.2.141:20000`. Either match
address-selection branch then targets that relay endpoint. Packet lengths,
sequence fields, padding, the other local endpoints, and the NAT type were
preserved. The rebuilt capture still authenticated and decrypted **402/402**
peer packets; only the intended join-accept plaintext changed.

```sh
python3 tools/svr_relay_rewrite.py work/svr-rng-test.pcap \
  --host 192.168.2.141:47908 --relay 192.168.2.141:20000
```

The initial separate match-protocol packets also use the original two peer UDP
endpoints in this capture (85 non-DTLS packets observed). That supports reusing
the existing relay forwarding and mapping proofs after fixing the target address.
It does not establish a completed live match through the relay.

### Experimental server integration

`internal/svrpeer` implements the same recovery and rewrite in Go. Enable it with:

```dotenv
ANGELWARE_STUN_MODE=relay
ANGELWARE_SVR_RELAY_REWRITE=on
```

`adaptive` also installs the hook, but it runs only on an already admitted relay
pair. Auth records successful-login seeds in a bounded, expiring cache. The relay
observes `COOKIE_ECHO` and `COOKIE_ACK`, looks up the room key from matchmaking,
and checks regenerated private keys against the actual public key. Multiple
logins behind one public IP are handled as candidates, not equated with one player.

Once the traffic key is established, the hook verifies the HMAC, decrypts DATA,
replaces both host local/public endpoints in the room-bound 0x4f message,
re-encrypts, and signs the result. Ordinary match packets pass through untouched.
Key recovery has a work/time budget; unsupported layouts and unavailable keys
remain unchanged and therefore do not provide a working forced relay route.

The setting defaults to off. Both clients must sign in after the server starts
with the setting enabled. Runtime tests used the captured handshake, login seeds,
and encrypted session packet, including a simulation with both auth/UDP clients
sharing one public IP. The Go output matched the independently recovered traffic
key, its HMAC verified, both embedded host targets changed, and tampered data
remained unchanged.

The regular Go suite also generates a synthetic login, ECDH handshake, and
encrypted join-accept for distinct and shared public IPs. It checks both host
records and the complete re-encrypted/HMAC-signed packet against the expected
relay endpoint, and rejects tampered traffic. GitHub CI runs this test with the
race detector; no private capture is required.

Run the private fixture test with:

```sh
ANGELWARE_TEST_SVR_PEER_FIXTURE=/absolute/path/to/fixture.json go test ./internal/svrpeer -v
```

### Live relay confirmation (2026-11-12)

The local test server ran forced-relay mode with this hook enabled. Both clients
signed in, hosted/joined a fresh room, and the user reported that the match
started. The server logged key establishment in approximately 14 ms and a
two-copy host address rewrite to `192.168.2.141:20000`.

The first scheduled capture had expired before this later test, so a new
20-second capture was taken during the match. It contains 11 exactly matched
incoming/outgoing **non-DTLS match-protocol datagrams**, in both directions:

```text
192.168.2.141:35665 -> relay :20001 -> :20000 -> 192.168.2.110:3074
192.168.2.110:3074  -> relay :20000 -> :20001 -> 192.168.2.141:35665
```

These were 10- and 14-byte match-protocol packets with identical forwarded
payloads. The relay flow counters continued increasing after startup. This
confirms that the separate match transport used the relay, rather than merely
the DemonWare lobby connection. Local evidence is in the ignored files
`work/svr-relay-live-evidence.log`, `work/svr-relay-match-check.pcap`, and
`work/svr-relay-match-check.report.json`.

Remaining validation: finish a complete match and verify result/stat submission.
The clients' auth and UDP public IPs must correlate for uncached key recovery;
IP-pool NAT, very long-lived keys with distant PRNG offsets, fragmented session
messages, larger rooms, and mid-match route migration are not yet validated.

### Stronger relay-health evidence: game acknowledgements

The 20-second live match capture also contains **six native game-packet
acknowledgements**, three from each console. Five complete request/forward/ACK/
return-forward cycles are present; the first ACK's outgoing copy is absent from
the capture. This is stronger than a relay byte counter: the receiver identifies
the forwarded packet's sequence and generation in its reply.

`NET 0x1aff8` (`_analaysisOfUserDataAckProtocol`) confirms that the ACK's two
payload bytes are compared with the queued packet's sequence and generation.
The outer game header is eight bytes; its payload length is big-endian at bytes
2..3, sequence is byte 0 and generation is byte 6. The big-endian protocol field
at bytes 4..5 is `0x0002` for DATA and `0x0802` for its ACK, whose payload is two
bytes. Byte 5 was previously described here as a version byte; the match-start
dispatcher below establishes that it is part of this protocol field. The
receiver's game socket and relay endpoint must
also match; a matching number from another endpoint is not accepted as proof.

```sh
python3 tools/svr_relay_health.py work/svr-relay-match-check.pcap \
  --output work/svr-relay-health.json
```

The checker is offline and does not inject packets or alter running adaptive
decisions. The existing 0x0b/0x0c mapping challenges can preflight both relay legs.
Native game DATA/ACK observations establish that the game transport used them.
`NET 0x23f88` also implements game-level `USERDATA_PING` / `USERDATA_PING_ACK`,
but injecting those would require preserving the live reliable-transport state;
an arbitrary encrypted packet is not automatically a valid probe.

A successful server-to-console probe does not prove that the two consoles can
connect directly. The server cannot passively observe direct peer ACKs that do
not traverse it. Adaptive still uses the native traversal retries to infer a
failed direct attempt; an equally strong direct-path decision would need game
feedback about that peer path. A relay-leg timeout alone should be treated as
inconclusive until the real end-to-end game path is tested.

### Lobby heartbeat and direct-path test

The DemonWare unicast connection also has a heartbeat: `LBYM 0x8bee0` creates
chunk type 6 after idle time; its constructor is `0x921d0`, and its serializer
at `0x92270` writes kind, flags, and a reserved zero u16. That request has no
destination address or arbitrary return-address field. It uses the connection's
existing resolved peer route; sending it on a relayed association tests that
association, not an unrelated direct address.

### Server-triggered direct probe: feedback requirement

Further inspection of the retail client's traversal dispatcher (`LBYM
0x3a4c8`) distinguishes a trigger from a server-visible result:

* Receiving `0x0b` makes the client copy the packet as `0x0c` and send it to
  the embedded source IP, sweeping ten ports from the source port minus five
  through source port plus four. The command's authenticator is not checked
  before sending. A server can therefore cause a console to send a challenge
  directly toward its peer, from the game's actual UDP socket.
* Receiving `0x0c` checks the client's own traversal HMAC (`0x3c8d0`) and looks
  up an outstanding local traversal by ID. Success invokes local listeners
  (`0x39760`); the handler does not send a result to the introducer. An
  arbitrary server challenge arriving at the peer does not become a result
  report or an echo back to the server.
* Receiving `0x0d` checks the local common-address ID and returns `0x0c` to
  the UDP sender. This tests the sender-to-console path, so sending it from
  the server does not measure the console-to-console path.

The QoS dispatcher (`0x2fe68`) similarly handles `0x28` requests and `0x29`
replies. A request handler (`0x306d0`) replies to its UDP source; the reply
handler (`0x308b8`) requires an outstanding local probe and the expected source
address, then invokes a local callback. These handlers do not provide a
server-directed request to probe a third endpoint and return its outcome.

These individual probe handlers do not supply an independent receipt channel
for a server-triggered direct-path decision. A receipt must come from another
mechanism: see the native session-consistency mechanism tested below. An
external packet observer is another possibility. An observer must see the
unpredictable challenge arrive on the receiving console's game path in both
directions; observing packets leave the sender, or receiving both consoles'
relay mapping echoes, is insufficient. Any report must be bound to the current
pair and probe attempt, expire promptly, and distinguish missing observation
from proven delivery failure. The current adaptive implementation continues
to use native traversal retries and verified relay mappings. The offline
capture checks below do not change that runtime decision.

Keeping only the tested peer association through the relay does not itself
fill this gap.
The relay can observe a challenge and response on `A -> relay -> B -> relay -> A`,
which measures that relayed path. It cannot observe `A -> B -> A` when those
packets bypass it. A hybrid check could use the relay to carry a receipt for a
directly received challenge. The traversal, QoS, and heartbeat handlers do not
send that receipt over a separate connection or accept an independent reply
destination. Session membership has a separate consistency broadcast, however;
the three-client test below demonstrates that distinction.
Server-to-console reachability, matching public IPs, and NAT classification
must not be recorded as successful console-to-console delivery.

### Stock-client feedback available through traversal retries

There is nevertheless useful negative feedback during an ordinary connection
attempt. The traversal update loop (`LBYM 0x3ace8`) waits more than 0.9 seconds
between retry actions. While introduction-based traversal is unresolved (state
2), it calls `0x3c300` again. That function sends another signed `0x0a` request
to the introducer, identifying the same target. A validated `0x0c` response
invokes the success listeners and removes the pending traversal (`0x3a4c8`),
ending its retries. Exhaustion invokes the local failure listeners (`0x39850`)
and removes the pending traversal; this checked path does not send a distinct
terminal failure packet to the server.

Repeated `0x0a` requests therefore tell the server that the client was still
waiting for traversal resolution when it sent them. This is stronger than
assuming failure from server-side silence, though delayed or duplicate UDP
requests are still possible. `internal/stun/adaptive.go` already uses this
signal: a repeated identical introduction after `DirectWindow`, with both relay
mappings proved, permits a relay resolution using the client's original signed
bytes. That provides stock-compatible fallback without a positive direct-path
report. It covers initial traversal; a successful lobby traversal followed by a
failure on the separately selected match address need not produce those retries.

### Session-consistency receipts over a separate relayed host connection

A broader handler audit found a native reporting path outside the probe
handlers. `LBYM 0x47200` dispatches session DATA messages `0x0a` (join),
`0x0b` (join reply and peer list), and `0x0c` (session consistency). These are
encrypted message types inside a DATA chunk, **not** the similarly numbered
unencrypted traversal datagrams.

`0x47870` consumes the join reply, creates connections to its listed peers,
and records pending connections. The success callback at `0x45720` removes a
completed connection from that list; when the list empties, it adds local
session data and broadcasts consistency. `0x45160` sends that data to the
other members over their existing associations. The consistency receiver at
`0x48e88` can also attach a newly connected member, recompute local session
data, and broadcast it to the other members. Thus one connection's completion
can cause a report on a **different** connection, including a relayed one.

The configured session-data factory (`0xb9d08`, installed by lobby-manager
initialization) creates the base `bdSessionData`. Its serialization at
`0x4abc0` is one u32. The value is computed at `0x4ae90` as an ordered weighted
sum of peer common-address IDs, modulo 2^32:

```
sum((index + 1) * common_address_id(peer[index]))
```

It is a topology consistency value, not a nonce, a cryptographic digest, or a
per-link success bitmap. The consistency checker at `0x44c40` compares member
data and selects session state READY (5) or NOT_READY (4). Title update
`0x15dd8` checks the READY predicate (`0x13838`, reading session state through
`0x43678`) and the delivery-manager state before sending title join `0x4e`
through `0x16bb0`. A consistency message must therefore be interpreted with
the current join, roster, connection state, and known route ledger; matching
u32 values in unrelated packets are not a direct-path proof.

The live stock-client test on 2026-11-12 used three clients:

| Member | Native UDP endpoint | Route to room host |
| --- | --- | --- |
| A, actual room host | `192.168.2.141:59386` | local host |
| B, laptop guest | `192.168.2.110:3074` | relay |
| C, third emulator guest | `192.168.2.141:50578` | relay |

Temporary firewall rules blocked only direct A/B and A/C UDP tuples before
joining. Native introduction retries caused the existing adaptive code to
offer relay after about 1.8 seconds for each pair; both relay flows started.
The B/C path was left open, and no B/C relay route was offered during this
positive test. The capture showed C/B's direct DTLS exchange at
19:45:18.806877Z and 19:45:19.123637Z, followed by authenticated traffic in
both directions. At 19:45:19.510842Z C sent consistency value `0x4b105b0b`
to A through its relay connection; B sent the same value through its own
host relay connection at 19:45:19.527036Z. C's title join `0x4e` followed
through the relay at 19:45:19.927864Z. The earlier two-member value was
`0xda3cfe63`.

This demonstrates the requested independent receipt path for a real
three-member prematch mesh: the receiving guest reports its updated session
view to the host over a separate relay association after the guests connect
directly. The offline decoder authenticates each observed encrypted datagram
and supports multiple peer keys, relay endpoint aliases, and reused UDP ports.
Private keys and plaintexts remain in ignored `work/` files.

The blocked-path control used a fresh room with direct B/C UDP blocked as
well. C joined first, then B. B received the native peer list at
19:48:44.363891Z, retried its introduction to C, and received a relay offer
at 19:48:49.812712Z. The B/C relay flow started at 19:48:49.830375Z. B's
three-member consistency report (`0xd9a95f42`) arrived through its host relay
at 19:48:50.564033Z; C's matching report followed at 19:48:50.586736Z.
No three-member consistency report from either guest was decoded between
the peer-list reply and the B/C relay offer. B's title join `0x4e` followed
at 19:48:50.861249Z. The two-member value before B joined was `0xbd0af5f5`.
The changed join order explains why the final value differs from the
positive run; a value is not portable between rosters/orders.

Both controls therefore completed their mesh and reported the result, but
on different routes. A consistency report alone cannot classify a route as
direct: the observer also needs the current pair's relay-offer/admission
history and must account for cached associations and earlier attempts. This
test validates a reporting mechanism and native fallback, not a new runtime
decision rule. The dedicated temporary firewall table was removed after
the controls. The three-client gameplay transition requires a separate GSS
handshake/ACK check.

The game mode required four participants, so the third emulator was shut
down and the gameplay checks used two clients. In a fresh 1-on-1 room, only
the direct A/B UDP tuple was temporarily blocked. Adaptive offered relay
at 19:53:58.353774Z and rewrote both host-address copies at
19:53:59.644669Z. The GSS connection request entered the relay at
19:54:13.203373Z and was forwarded to A at 19:54:13.203435Z; A's connection
ACK returned at 19:54:13.224999Z and was forwarded to B at
19:54:13.225078Z (21.705 ms total). The captured DATA/ACK sequences verify
**22 complete relay request/receiver-ACK/return cycles across both directions**,
and the tester confirmed both clients reached controllable gameplay. This
validates adaptive fallback followed by actual match use of the relay, rather
than forced-relay configuration or lobby traffic alone. The two-client block
was then removed for a fresh direct comparison.

For the direct comparison, both clients signed out and in. The host's new UDP
endpoint was `192.168.2.141:34723`; B remained `192.168.2.110:3074`. The fresh
room was created at 19:56:24.386494Z. Its introduction ended with one request
and **zero relay offers**, and the captured lobby DTLS handshake completed
directly. The GSS request at 19:56:50.706416Z received a direct ACK at
19:56:50.725507Z (19.091 ms). The inspected interval contained **19 matched
DATA/ACK cycles across both directions**, with **zero native game packets on
relay ports after the fresh-room boundary**. The tester confirmed gameplay.
The capture begins with the previous relay match's tail, so that boundary is
essential when reproducing the comparison. Evidence is saved in
`work/svr-two-player-adaptive-direct-game-health.json`, the relay counterpart
`work/svr-two-player-adaptive-relay-health.json`, and their packet captures.
All temporary firewall tables and capture containers were removed; the local
server remains in adaptive mode with the existing relay address rewrite on.

This is not yet a general two-player preflight implementation. With only two
members there is no separate native member connection carrying the report
while their sole association uses the direct path. A server acting as a
coordinator would need a valid additional session association and carefully
validated membership/host behavior, without adding a fake playable participant
or disturbing the later match handoff. No such virtual coordinator was deployed
by this test. The stock host-count observer below provides a separate
two-console reporting mechanism without adding a member. A prematch
DemonWare receipt also does not prove the separate
GSS match address selected later will work.

Failure handling is less informative. `0x46138` records a local session error
and calls cleanup (`0x4a0d8`); the title failure callback `0x171d0` similarly
sets a local error and calls `0x13988`. No distinct server-directed terminal
failure message was found in these paths. Missing consistency alone is
inconclusive; native traversal retries and observed relay fallback remain
separate evidence.

### Stock host reports: the two-console observer

`ANGELWARE_SVR_OBSERVER=on` enables a server observer of the stock host's
existing authenticated matchmaking updates. It adds no native member, alters
no slots, opens no extra UDP ports, and requires adaptive mode with relay
address rewriting enabled. Its implementation is in `internal/lobby/observer.go`
and `internal/stun/observer.go`.

The native source of the count is explicit: `LBYM 0x13538` reads
`bdSession::getNumPeers` (`0x43688`); `0x1b220` wraps that getter. The update
scheduler at `0x1bcf8`, called by `CLobbyManager::AsyncUpdateSession` at
`0xd398`, copies the room info and stores that native peer count at copied
info offset `+0x78` (`0x4a70 - 0x49f8`). Serializer `0x276c0` copies this
value to the public/private used-slot field. The host consequently reports
native membership to the server after a successful peer join.

In a clean two-stock-client room `aaa01a12fa5095da`, with the extra-peer
prototype disabled, the host published counts `0 -> 1 -> 2`. The guest's
native session join was sent at 20:58:14.764558Z, accepted at
20:58:14.785934Z, and followed by guest/host consistency at
20:58:14.824901Z / 20:58:14.832360Z. Title join and accept followed at
20:58:15.348941Z / 20:58:15.378461Z. The authenticated gateway update
reported two native peers at **20:58:15.863798Z**. These observations tie
this existing server-directed report to completed native peer traffic;
this is not a new arbitrary ping RPC.

The server accepts a completion event only from the room's gateway owner,
for a fresh two-slot room changing from fewer than two native peers to two.
The host's public endpoint must match its owning gateway's IP and remain
unchanged. It tracks which other gateway connections were given this room's
key through actual search results or find-by-ID replies. With more than one
recipient, attribution remains unmeasured; it never guesses which guest won
a join race. Friend invitations carry the room ID and use find-by-ID to
retrieve the key, so that path is included.

Adaptive further requires the one guest IP to identify exactly one live,
registered non-host UDP endpoint. Shared IPs with multiple candidate endpoints
are inconclusive. A current relay admission also prevents a direct claim:
that case is logged as `relay-available`, since an offer alone does not prove
which route won. With no relay admission and an unambiguous pair, it records
native completion on the direct path. Only a matching outstanding signed
traversal begun in this room generation gets a direct-receipt flag, suppressing
additional offers for that same attempt. A new nonce, attempt, or room does
not inherit it. Missing reports retain the existing native-retry fallback.

This is a conservative observer of the normal prematch connection attempt,
not a forced ping before joining and not proof of the separately selected
GSS match address. It depends on unmodified stock-client behavior, fresh room
and registration state, and unambiguous identity mapping; ambiguous public
rooms remain unmeasured. It does not treat gateway silence or a server-leg
mapping echo as a console-to-console failure or success.

The observer-enabled live tests on 2026-11-12 passed both routes. Room
`fd0f9a04e5b9f647` produced `path=direct, current_traversal=true` at
21:03:43.225160Z, with one introduction and zero relay offers. Both consoles
then reached gameplay; the direct GSS handshake took 29.571 ms and the
inspected interval contained 22 matched DATA/ACK cycles across both
directions, with no game packets on relay ports.

For room `93b310aaad21aab1`, a temporary firewall blocked only
`192.168.2.141:42751 <-> 192.168.2.110:3075`. Its counters recorded eight
dropped direct packets. Native retries triggered one relay offer after
1.806 seconds, the encrypted host addresses were rewritten, and the host's
count report produced `path=relay-available` at 21:09:00.389804Z. Both
consoles reached gameplay. The GSS request/ACK crossed both relay legs in
26.757 ms, and the final capture verifies **27 complete relayed game
DATA/receiver-ACK/return cycles across both directions**. All 2,103 captured
encrypted native peer datagrams authenticated in the offline decoder.

The summary is `work/svr-stock-observer-evidence.json`; game checks are
`work/svr-stock-observer-direct-health.json` and
`work/svr-stock-observer-relay-health.json`. Private captures, decrypted
traffic, keys, and raw debug logs stay in ignored `work/` artifacts. The
local server is left in adaptive mode with rewrite and stock observation
on; temporary direct-path blocks and task captures were removed.

### Rejected extra-peer observer prototype

A native observer peer was implemented and tested before the stock count
report was identified. Its DTLS/ECDH/unicast and session join worked with a
stock host; the capture independently authenticated 3,209 encrypted packets.
It did not send title player join `0x4e`, but the host still counted it toward
native capacity. The initial room disappeared from search after the host
reported `[public max=2, used=2]`. Subtracting the observer from advertised
occupancy made the room visible but could not change the host's local gate:
the real guest received native `0x0b` with `accepted=false` and error
`0x40000003` twice.

`LBYM 0x16ec0` checks `bdSession::getNumPeers < CLobbyManager.maxPeers`
**before reading any join payload**. `0x15d48` initializes that local maximum
from the game mode. A stock 1-on-1 room therefore cannot hold the host,
observer, and real guest through this approach. The capacity-masking change
and the active native observer were removed from the runtime. The diagnostic
prototype is archived only in ignored `work/native-observer-prototype/`;
its transport success must not be described as a working two-console preflight.

### Match-start boundary and the actual GSS handshake

The menu-to-match transition was traced further in the retail overlays:

1. `OMEN 0x3158` chooses the host address and port from session information,
   including the equal-public-IP branch selecting the first local endpoint.
   It stores the chosen target separately from the console's own bind port.
2. `OMEN 0x43648`, case 3 / step 4 (call at `0x43cac`), calls menu/lobby
   cleanup (`0x32f38`), destroys and clears `_g_pDllCtrlLobbyMan`, then calls
   `0x30e8` to initialize GSS with that saved address. The later GSS result
   therefore cannot be assumed to travel through the former lobby connection.
3. `NET 0x1280` (`SetMatchInit`) copies the target and changes the controller
   state to `0x15`. `CGssCtrl::GssCtrlSync` (`0x2370`) initializes the match
   socket and calls `gssMatchConnect` (`0x20288`).
4. The native EUDP receive dispatcher (`0x1b3a0`) distinguishes connection
   requests (`0x0001`), connection ACKs (`0x0801`), rejection (`0x8001`), DATA
   (`0x0002`), and DATA ACKs (`0x0802`). `0x1ac38` accepts a connection ACK only
   while connecting (socket state 3) and when its source sockaddr matches the
   expected peer, then sets connected state 5. The shared receive loop at
   `0x1b6a8` dispatches by the expected peer address, with a fallback for a
   listening socket (state 4), rather than sending unknown-source packets to
   every active connection.
5. Match connection errors pass through `0x27040`, which closes the relevant
   GSS socket(s), sets the local error value, and optionally prints diagnostics.
   The inspected error/controller paths do not send a distinct failure report
   to the DemonWare introducer or retry its `0x0a` introduction.

The original `work/svr-rng-test.pcap` already contains this separate match
handshake: `192.168.2.110:3074 -> 192.168.2.141:47908`, a nine-byte connection
request followed by a nine-byte ACK **28.6 ms** later. Subsequent DATA has **40
matched sequence/generation ACKs across both directions**. Its evidence report
is `work/svr-match-start-audit.json` (ignored). This establishes the observed
match path, beyond the earlier DemonWare lobby handshake; it is not a new
server-visible preflight.

A synthetic GSS connection request is not a harmless ping: a listening console
can adopt its sender as the match peer and leave listening state (`0x1aa88`).
Sending one from a relay endpoint could consume the connection intended for the
real opponent. Conversely an ACK sent from the relay cannot simply replace an
ACK expected from the direct peer address. These packets must not be injected
as an adaptive reachability probe without a separately validated state-machine
design.

In the current server implementation, the decision point is before lobby teardown:
use native traversal retries to offer a relay, and bind an already relayed
pair's host session addresses to that relay before the match target is saved.
Both address copies and both selectable endpoint fields matter. A session
consistency receipt through a separate member can report prematch mesh
completion, as tested above, but does not establish the later GSS address's
reachability. A policy that needs to avoid relying on that unobserved path must
choose relay conservatively; a timeout after GSS starts is too late to treat as
an ordinary lobby-introduction fallback. Forced relay is already implemented;
this investigation does not change adaptive routing or deploy a new policy.

### Captured direct-path test

The local test override was switched from forced relay to `adaptive` for a fresh
native direct-first connection experiment. Both clients must sign in and join a
fresh prematch room. Capture evidence can be summarized with:

```sh
python3 tools/svr_path_probe.py work/svr-direct-probe.pcap
```

The checker requires INIT, INIT_ACK, COOKIE_ECHO and COOKIE_ACK between the same
direct endpoints, followed by encrypted traffic in both directions. Missing
evidence is inconclusive, not proof that direct connectivity is impossible.
The original direct capture passes this check with 402 peer packets; removing
COOKIE_ACK must make it fail. This observes the native lobby peer path; the
game's later choice of a match IP/port still needs its separate checks.

### Live adaptive direct-match confirmation (2026-11-12)

After the restart-related LAN DNS firewall rule was restored, the clients
signed in, joined a fresh room and started another match with the local server
in `adaptive` mode. The server recorded the native direct introduction and no
relay route offer or relay flow for this attempt.

The earlier long capture had expired, so a fresh 30-second match capture was
taken. It contains 14 native game DATA/ACK packets directly between
`192.168.2.141:46215` and `192.168.2.110:3074`, including seven matched
sequence/generation ACKs across both directions. No captured packets use relay
ports 20000..20199. Evidence: `work/svr-adaptive-match-check.pcap` and
`work/svr-adaptive-match-check.report.json` (ignored by git).

This verifies the direct branch of adaptive for this local pair, including
match-transport delivery. Forced-relay startup was verified separately above;
automatic fallback on a live pair with genuinely blocked direct connectivity
has not yet been validated.
