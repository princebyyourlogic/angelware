# SmackDown vs. Raw 2007 (PS2, SLUS-214.27 v1.01): online analysis

Reverse-engineering notes for the retail US disc, started 2026-11-11. Ghidra and PCSX2 findings; see "Verified in PCSX2" for what has run against the game.

## Disc layout

- `SLUS_214.27`: main ELF at 0x100000. It contains no network code.
- `BIN/BIN.PAC`: a `DPAC` container holding 22 overlays. The table is `OVRM` at 0x800, with
  entries of `name[4], u16 start, u16 size`. The data is at `0x4000 + start*0x800`. Each overlay is
  `PAC ` + `BPE ` (Gage-style byte-pair encoding, big-endian block sizes) and decompresses
  to an `SNR2` relocatable module. `tools/unpac.py` extracts all 22 overlays into `disc/overlays/`.
- `PAC/MODULE/*.IRX`: the standard SCE network stack (DEV9, SMAP, INET, NETCNF, PPP/PPPoE) plus
  `DNAS300.IMG`.

| Overlay | Size | Role |
| --- | --- | --- |
| `LBYM` | 0x120673 | `LobbyManagerPS2Dll.elf`: **all DemonWare code** (SDK `DemonWare-ps2-1.75`) |
| `NET`  | 0xd0693  | Network setup: libeenet/DHCP/PPPoE, Your Network Configuration file |
| `DNAS` | 0x131185 | DNAS 3.00 auth client |
| `MAUT` | 0x28391  | Memory card/menu (`SDvsRAW.ico`), not network auth |

SNR2 code is linked so that addresses are equal to file offsets (`lui 0xd; addiu 0xb9c8` = file offset
0xdb9c8). Raw disassembly at base 0 therefore works. The runtime load base is not known yet;
take it from a PCSX2 memory dump.

### SNR2 format (see `tools/snr2.py`)

The header holds a relocation table (12-byte rows of `offset, type | sym << 8, addend`) and a
symbol table (12-byte rows of `name, value, hash`). LBYM has 1368 relocations, all
R_MIPS_26/HI16/LO16, and **every one targets an undefined symbol**. They are the 72 imports from
the main ELF and the `NET` overlay (`sceEENet*`). Internal references are absolute, which
is why base 0 lines up.

Symbol names, and every "garbled" string seen earlier, are **GCC 2.9x-mangled C++ names
obfuscated with a repeating 11-byte additive key** over the printable characters 0x21..0x7e:
`6,62,62,17,93,10,79,69,86,62,13`. Example: `sEM&d~` is `memset`. The main ELF has an export table of
3854 entries in the same form at file offset 0x2502d8, which resolves 49 of the imports. Ghidra's
bundled `demangler_gnu_v2_24 -s gnu` demangles them.

## Addresses

Addresses in these notes are offsets into the decompressed `LBYM` overlay loaded at base 0 in Ghidra
(`r5900:LE:32:default`, code up to 0xce040), with the 469 exported symbols from `tools/snr2.py`
applied. The Ghidra project and scripts are kept outside the repository.

### Game-facing API: `nLobbyManager::CLobbyManager` (0xb3a8..0x10ad8)

This lists what the server must eventually answer:
`CreateAccount(name, password)` and `AuthAccount(name, password)`, which use **plain DemonWare
username/password accounts**, not a PS2 or DNAS identity. Then `GetUserID`; `CreateProfile` / `DeleteProfile` /
`SetPrivateProfileInfo` / `ReadPrivateProfileInfo`; `CreateSession` / `UpdateSession` /
`SearchSession` / `SearchByInviteSession` / `JoinSession` / `LeaveSession`; friends (`ProposeFriend`,
`Accept/Reject/WithdrawProposeFriend`, `RemoveFriend`, `LoadFriendList`, `LoadFriendProposeList`);
`SetBlockUser` / `LoadBlockUserList`; `SendFriendMessage`; `InviteGameSession` / `Accept/RejectInvitation`;
`WriteStats` / `DeleteStats` / `ReadStatsByID` / `ReadRankingByRank`; `WriteDna`; storage
(`Upload/Update/UpdateParam/Remove/DownLoadStorage`, `ReadStorageListByUser/ByPublisher`);
`ProbeSessionQoS`; in-match messaging and `StartRound` / `EndRound`.

### Auth and LSG connect path

1. `LobbyTask_StartAuth` (0x22560) resolves `...auth.mmp.demonware.net`, builds a `bdAddr` with
   port **3074** and creates `bdAuthService(titleID = 4669 (0x123d), addr)`. **4669 is the
   DemonWare title ID**, not a port. A mode field selects one of four requests (create account,
   auth account, and two more).
2. `bdAuthService` (0x71e10..0x74c00) sends each request over a **TCP `bdStreamSocket`**,
   one connection per request. It has nine request builders with **even message types**
   0, 2, 4, 6, 8, 10, 12, 14 and 16. Each writes a typed bit-buffer: u32 random value, u32 title ID, a
   64-bit id derived from the name, then an encrypted blob. In type 0 the blob is the 0x60-byte
   (name[64] + password-derived data) block, keyed by password-derived data
   (`FUN_0007b318`; Tiger/3DES are in the SDK).
3. Replies use **type + 1**. `handleReply` (0x74590) reads a u32 status, where **700 = success**. Type 13
   carries a 0x400-bit (128-byte) encrypted ticket plus session key material, decrypted with the
   client's key and checked against a magic constant (`DAT_000e6270`).
4. `LobbyTask_PollAuthThenConnectLsg` (0x22a08) creates `bdLobbyService` and calls
   `bdLobbyService::connect(lsg.mmp:3074, ticket)`.

The STUN path (`bdIPDiscoveryClient` etc.) has not been traced yet.

## Wire protocol (auth and lobby gateway)

**Framing** (`bdAuthTransport` send 0x896d8 / receive 0x8a068): `u16 LE length, u8 encrypted`, then
either `u8 type, payload` (length = payload + 2) or `u32 seed, ciphertext` (length = ciphertext + 5).
The ciphertext is 3DES-CBC over `u32 0xDEADBEEF, u8 type, payload`, padded to 8 bytes, with
IV = Tiger(seed). The seed is a per-connection counter starting at 0. The receive path takes plain
and encrypted frames in any state, so **the server can always answer in plain text**.

**Payloads** are bdBitBuffers packed LSB first. Bit 0 says whether fields carry 5-bit type
markers (3 = u8, 8 = u32, 12 = ranged u32). Auth messages are untyped. Lobby tasks are typed.

**Auth requests** (even types; reply = type + 1, starting with `u32 status`, 700 = OK):

| Lobby call | Task | Request | Reply | Body |
| --- | --- | --- | --- | --- |
| `CreateAccount(name, pw)` | 10 | 0x00 | 0x01 | seed, title, 64-bit id (0), 0x60-byte block `{0xDEADBDEF, name[64], Tiger(pw)}` encrypted with the fixed key `DEADBEEF`x4 + 8 zero bytes. Reply is status only |
| change password (`0xc3e8`) | 11 | 0x02 | 0x03 | seed, title, Tiger(name)[:8], 0x20-byte `{magic, Tiger(new)}` under Tiger(old) |
| delete account (`0xc548`) | 12 | 0x06 | 0x07 | seed, title, Tiger(name)[:8], 8-byte `{magic}` under Tiger(password) |
| `AuthAccount(name, pw)` | 13 | 0x0A | 0x0B | seed, title, Tiger(name)[:8]. **No encrypted part** |

Ticket replies 0x0B and 0x0D carry `u32 seed`, a 0x400-bit block decrypted with Tiger(pw), and a 0x400-bit
opaque lobby ticket. Reply **0x11** carries the same block **unencrypted**. `handleReply` dispatches on
the reply type without checking which request is pending, so answering 0x0A with 0x11 logs the
client in without any crypto. The block is packed with no padding: `0xDEADBDEF, u8, u32 (kept, sent
to the gateway), u32, u32, u64, u64, name[64], session key[24]`. Only the magic is checked.

**Lobby gateway:** after TCP connect the client sends message 7 `{u32 ticket.a, u32 ticket.seed,
0x400-bit lobby ticket}`. It then installs the session key from the block for its own sends. Server
messages: type 1 = task reply, type 2 = push. Client tasks are sent **encrypted** with a typed header
`u8 slot, u8 sequence, u8 task id` (`FUN_0006da20`), then the task arguments and a trailing u32.

**Lobby services** are message types; the task id is the third header byte. Senders found by the
calls to `FUN_0006da20` (service in a2, task in a3):

| Service | Tasks | Notes |
| --- | --- | --- |
| 3 | 1-27 | 0x77188..0x789a8 |
| 4 | 1-9 | **Stats**: lobby tasks 0x22-0x29 and `WriteDna` (4/1). 4/3 reads stats by user id |
| 5 | 1-6 | **Matchmaking**: 1 create, 2 update, 3 delete, 4 find by id, 5 find (Quick Match), 6 (u32, u32) |
| 6 | 1, 4-6 | Polled every second (6/1: u8, u32 0, u32 20, bool, bool); lobby tasks 0x2c-0x2f |
| **8** | 1-7 | **Profiles**: lobby tasks 0x0e..0x14 (`CreateProfile` = mode 0 = task 1, `DeleteProfile`, `SetPrivateProfileInfo`, `ReadPrivateProfileInfo`) |
| 9 | 1-19 | Friends/messaging (lobby tasks 0x15-0x21) |
| 10 | 1-8 | Storage (`CDWStorageProcess`) |
| 11 | 1-6 | 0x76728..0x76ba8 |
| 12 | 1-4 | 0x71430..0x71840 |

**Task reply** (message type 1, typed): `u8 slot, u8 seq` (echo the request's), `u32 error` (0 = ok),
`u8 count`, then result objects that the task deserializes (`FUN_0006d308`).

**Lobby task ids** (`FUN_00019200` cases, from `CLobbyManager`): 1 Start, 2 End, 3 CreateSession,
4 SearchSession, 5 SearchByInviteSession, 6 JoinSession, 7 LeaveSession, 8 DeleteSession, 9 UpdateSession,
10 CreateAccount, 13 AuthAccount, 0x0e-0x13 profiles, 0x15-0x21 friends/invites, 0x22-0x29 stats,
0x31 WriteDna, 0x32-0x38 storage.

**Matchmaking (service 5).** A session info serializes symmetrically (DemonWare base 0x652c8/0x65480,
then the game's fields 0x27c90/0x281b0): blob host address[25], blob session id[8], blob session key[16], 4 x i32
slot counts, then i32s, a string, an i64, a 129-byte blob and more i32s. Matchmaking replies (0x64ea0) are
`u32 error, u8 kind (1/4/5/6), u32 count`, then results. A create result is `blob id[8], blob key[16]`.
The test server stores the host's info with the id and key it assigned, and returns it to any other
player's search (no filtering yet).

**Profiles (service 8).** 1 create (u8, then the public fields), 2 read public (u8, u64 user id), 3 read private
(u8), 5 set private, 6 delete. The public result (0x26960) is `u64 id, i32, i32, blob[48]`, the same fields
CreateProfile uploads. The private result (0x26b18) is `u64 id, 4 x i32`. Both players read their private
profile after readying up; an empty reply leaves them on "please wait for match".

**Peer introduction** works as in codstun: joining sends UDP 0x0a to 3074, the server forwards it as 0x0b to
the host's keepalive endpoint, and the host answers the joiner directly. Verified 2026-11-11: two clients
(PCSX2 and a second machine on the same LAN) joined the same session and readied up.

## Endpoints

| Hostname | Port | Service |
| --- | --- | --- |
| `smackdownvsraw2007.us.ps2.auth.mmp.demonware.net` | TCP 3074 | bdAuthService, title id 4669 |
| `smackdownvsraw2007.us.ps2.lsg.mmp.demonware.net` | TCP 3074 | Lobby service gateway |
| `smackdownvsraw2007.stun.us.demonware.net`, `.stun.eu.` | UDP 3074 | IP/NAT discovery, introductions, keepalives |
| `stun.{us,eu,jp,au}.demonware.net` | UDP 3074 | Generic SDK fallbacks |
| DNAS (`gate1.us.dnas.playstation.org` etc.) | TCP 443 | Not angelware: the community replacement behind 45.7.228.197 |

All DemonWare names must resolve to the angelware host; DNS is outside this project.

## Server

The Go service in `cmd/angelware` implements everything above; see the README for running it.
Tiger is the original 1996 variant (`github.com/cxmcc/tiger`, checked against the reference vectors).
3DES is Go's `crypto/des`, which accepts the signup key whose first two DES keys are equal.

### Verified in PCSX2 (2026-11-11, retail US v1.01, Python prototype)

DNAS via 45.7.228.197, STUN v2 (tests 1 and 3, Moderate), signup 0x00 (decrypts to the typed name; the
login id equals `Tiger(name)[:8]`), login 0x0A answered with 0x11, gateway hello with our ticket,
CreateProfile, a session hosted on one client and found by a second, introduction forwarding,
private profile read and set around the match (field 0 set to 1 before, back to 0 after), and nine
stats writes per player after the match. The keyed 0x0B login reply (`verify` mode) follows the client
code at 0x74590 but has not been run against the game yet.

## Open items

- Stats reads (service 4, task 3) and leaderboards: writes are stored; the read result layout is not decoded.
- Service 6 task 1 (polled every second, `u8, u32 0, u32 20, bool, bool`): probably messages/invites.
- Friends and messaging (service 9), invites, storage (service 10), services 3, 11, 12.
- Two server IPs for real NAT classification; with one IP every client reports Moderate.
- Matchmaking search ignores the query's filters.
- Real auth status codes for duplicate names and wrong passwords (701 is a placeholder).
