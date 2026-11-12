-- Applied on every start; keep statements idempotent.

CREATE TABLE IF NOT EXISTS accounts (
    user_id        bigint PRIMARY KEY,          -- Tiger(name)[:8], uint64 stored as bigint
    name           text NOT NULL UNIQUE,
    password_tiger bytea NOT NULL,              -- password-equivalent: protect backups
    created_at     timestamptz NOT NULL DEFAULT now(),
    last_login     timestamptz
);

CREATE TABLE IF NOT EXISTS profiles (
    user_id     bigint PRIMARY KEY,
    public_a    integer,
    public_b    integer,
    public_data bytea,
    private     integer[],
    updated_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS stats (
    user_id    bigint NOT NULL,
    board      integer NOT NULL,
    flag       smallint NOT NULL,
    rating     bigint NOT NULL,
    vals       integer[] NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, board)
);
