# angelware

A replacement for **DemonWare**, the online backend used by a number of PS2 games, so those games can
play online again with an unmodified disc.

The first supported game is **WWE SmackDown vs. Raw 2007** (US, `SLUS-214.27`, v1.01).

| | |
| --- | --- |
| Account sign-up and login | ✅ |
| Online lobby, hosting and finding matches | ✅ |
| Joining and playing a match (peer to peer) | ✅ |
| Player profiles and match records | ✅ |
| Stats written after a match | ✅ stored |
| Leaderboards, friends, messages, invites | ⏳ not yet |

The retail game has been tested in PCSX2: two players signed up, found each other's session and played a
match. Protocol notes are in [docs/svr2007-analysis.md](docs/svr2007-analysis.md).

## How it fits together

```
 PS2 / PCSX2 ──DNS──▶ your DNS resolver ──▶ points the game's DemonWare names at angelware
      │
      ├── DNAS check ──────────▶ community DNAS replacement (not part of angelware)
      ├── TCP 3074  ───────────▶ angelware: sign-up, login, lobby
      └── UDP 3074/3075 ───────▶ angelware: NAT detection and connecting players
                                     │
                                 PostgreSQL: accounts, profiles, stats
```

angelware does **not** include a DNS server. You run your own and add the records below.

## DNS redirects

Point these names at the IP address of the machine running angelware (an `A` record or a DNS override):

| Hostname | Used for |
| --- | --- |
| `smackdownvsraw2007.us.ps2.auth.mmp.demonware.net` | Sign-up and login |
| `smackdownvsraw2007.us.ps2.lsg.mmp.demonware.net` | Lobby (matchmaking, profiles, stats) |
| `smackdownvsraw2007.stun.us.demonware.net` | NAT detection, connecting players |
| `smackdownvsraw2007.stun.eu.demonware.net` | NAT detection (the game asks for both) |

Optional, only used as fallbacks by the DemonWare library: `stun.us.demonware.net`,
`stun.eu.demonware.net`, `stun.jp.demonware.net`, `stun.au.demonware.net`.

**DNAS:** the game checks DNAS before going online. angelware does not handle this. Forward
`*.dnas.playstation.org` lookups (the game asks for `gate1.us.dnas.playstation.org`) to the community
DNAS replacement's resolver at **`45.7.228.197`**.

Everything else can resolve normally.

<details>
<summary>Example: dnsmasq</summary>

Replace `203.0.113.10` with your angelware server's IP.

```
address=/smackdownvsraw2007.us.ps2.auth.mmp.demonware.net/203.0.113.10
address=/smackdownvsraw2007.us.ps2.lsg.mmp.demonware.net/203.0.113.10
address=/smackdownvsraw2007.stun.us.demonware.net/203.0.113.10
address=/smackdownvsraw2007.stun.eu.demonware.net/203.0.113.10
server=/dnas.playstation.org/45.7.228.197
```

</details>

Then set the DNS server in the game's network configuration (or in PCSX2's network settings) to your
resolver.

## Running the server

You need Docker with Compose.

```sh
git clone https://github.com/princebyyourlogic/angelware.git
cd angelware
cp .env.example .env
chmod 600 .env
```

Edit `.env`: set `ANGELWARE_PUBLIC_IP` to the address players reach this machine on (your LAN IP for a
home test, the public IP on a VPS) and choose a `POSTGRES_PASSWORD`. Then:

```sh
docker compose up -d --build
docker compose logs -f angelware
```

Open these in your firewall: **TCP 3074**, **UDP 3074** and **UDP 3075**.

angelware runs with host networking so it sees each player's real address, which NAT detection needs.
PostgreSQL is only reachable from the machine itself. Stop with `docker compose down`; add `-v` only if
you want to delete all accounts and stats.

### Settings

All set in `.env`:

| Variable | Default | What it does |
| --- | --- | --- |
| `ANGELWARE_PUBLIC_IP` | required | IPv4 address players reach the server on |
| `POSTGRES_PASSWORD` | required | Database password |
| `ANGELWARE_BIND` | `0.0.0.0` | Address to listen on |
| `ANGELWARE_PORT` | `3074` | Main port, TCP and UDP (the game expects 3074) |
| `ANGELWARE_STUN_ALT_PORT` | `3075` | Second UDP port for NAT detection |
| `ANGELWARE_PG_PORT` | `55433` | Local-only port PostgreSQL is published on |
| `ANGELWARE_AUTH_MODE` | `verify` | `verify` checks passwords. `open` lets anyone log in as any name |
| `ANGELWARE_LOG_LEVEL` | `info` | `debug` logs every lobby request |

`verify` has not been tested against the game yet. If logins fail with it, `open` matches the behaviour
that was tested (but has no password check).

### Accounts and privacy

Players create their account from the game's online menu. The game never sends a plain password; it sends
a hash, which the protocol then uses as the login key. That hash is stored in the `password_tiger` column
and works like a password for this game, so keep the database and its backups private. angelware stores
no email addresses or real names.

## Development

No local Go install is needed; the toolchain runs in Docker:

```sh
scripts/go test ./...
scripts/go vet ./...
```

The PostgreSQL test in `internal/store` runs when `ANGELWARE_TEST_DATABASE_URL` points at a database.

| Path | Contents |
| --- | --- |
| `cmd/angelware` | Settings and startup |
| `internal/server` | TCP listener that sends each connection to login or the lobby |
| `internal/auth` | Sign-up and login |
| `internal/lobby` | Lobby connection, matchmaking, profiles, stats |
| `internal/stun` | NAT detection and connecting players |
| `internal/store` | PostgreSQL (and in-memory storage for tests) |
| `internal/bitbuf`, `frame`, `dwcrypto`, `session` | DemonWare's wire format, encryption and login tickets |
| `tools/` | Disc extraction helpers for reverse engineering. They need your own disc and are not used by the server |

### Game files

This repository contains no game code, disc images or assets. The reverse-engineering tools read files
from your own disc into `disc/` and `work/`, which are ignored by git.
Please keep it that way in contributions.
