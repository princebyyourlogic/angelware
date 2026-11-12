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

CREATE TABLE IF NOT EXISTS mailbox (
    id         bigserial PRIMARY KEY,            -- message id the game acknowledges
    to_id      bigint NOT NULL,
    type       integer NOT NULL,
    from_id    bigint NOT NULL,
    from_name  text NOT NULL,
    small      integer NOT NULL DEFAULT 0,
    data       bytea,
    data2      bytea,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS mailbox_to_id ON mailbox (to_id, id);

CREATE TABLE IF NOT EXISTS friend_requests (
    from_id    bigint NOT NULL,
    to_id      bigint NOT NULL,
    data       bytea,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (from_id, to_id)
);
CREATE INDEX IF NOT EXISTS friend_requests_to ON friend_requests (to_id);

CREATE TABLE IF NOT EXISTS friends (                 -- one row per direction
    user_id    bigint NOT NULL,
    friend_id  bigint NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, friend_id)
);

CREATE TABLE IF NOT EXISTS blocks (
    user_id    bigint NOT NULL,
    blocked_id bigint NOT NULL,
    level      smallint NOT NULL,
    PRIMARY KEY (user_id, blocked_id)
);

CREATE TABLE IF NOT EXISTS storage_files (          -- lobby service 10 uploads (trades)
    id          bigserial PRIMARY KEY,               -- file id the game refers to
    owner       bigint NOT NULL,
    name        text NOT NULL,
    flag        boolean NOT NULL,
    visible     boolean NOT NULL,
    data        bytea NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    modified_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS storage_files_owner ON storage_files (owner, id);
