-- GHGen full schema. This file is the source of truth: every table the
-- worker touches is created here. Apply with:
--   wrangler d1 execute greedyhudzell-keys --remote --file=./schema.sql
-- (All statements are IF NOT EXISTS, so re-running is safe. The worker
-- additionally self-applies additive tweaks at runtime — see
-- ensureMigrations() in src/index.js.)

-- Access keys (sold / handed out owner-side). plan = day|week|month|year.
CREATE TABLE IF NOT EXISTS keys (
    key TEXT PRIMARY KEY,
    username TEXT,
    plan TEXT NOT NULL DEFAULT 'day',
    expires_at INTEGER NOT NULL DEFAULT 0,
    revoked INTEGER NOT NULL DEFAULT 0
);

-- Dashboard accounts. key is FK-ish onto keys.key (one key, one account).
CREATE TABLE IF NOT EXISTS ghgen_users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key TEXT UNIQUE,
    roblox_username TEXT,
    ghgen_username TEXT UNIQUE NOT NULL,
    email TEXT,
    password_hash TEXT,
    salt TEXT,
    discord_id TEXT,
    email_verified INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    last_login INTEGER
);
CREATE INDEX IF NOT EXISTS idx_ghgen_users_key ON ghgen_users(key);
CREATE INDEX IF NOT EXISTS idx_ghgen_users_discord ON ghgen_users(discord_id);
CREATE INDEX IF NOT EXISTS idx_ghgen_users_email ON ghgen_users(email);

-- Cookie sessions.
CREATE TABLE IF NOT EXISTS ghgen_sessions (
    session_id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    ip_hash TEXT
);
CREATE INDEX IF NOT EXISTS idx_ghgen_sessions_user ON ghgen_sessions(user_id);

-- Email verification codes. attempts powers the 10-guess burn.
CREATE TABLE IF NOT EXISTS ghgen_verifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL,
    code TEXT NOT NULL,
    purpose TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    used INTEGER NOT NULL DEFAULT 0,
    attempts INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_ghgen_verifications_email ON ghgen_verifications(email);

-- Roblox account pool. payload is AES-GCM JSON {u,p,c,ci,ip,ck,age,created}.
CREATE TABLE IF NOT EXISTS ghgen_pool (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    payload TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'available',
    created_at INTEGER NOT NULL,
    region TEXT,
    age_days INTEGER,
    age_base_at INTEGER,
    issued_to INTEGER,
    issued_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_pool_status_region ON ghgen_pool(status, region);
CREATE INDEX IF NOT EXISTS idx_pool_status_age ON ghgen_pool(status, age_days);
CREATE INDEX IF NOT EXISTS idx_pool_issued_to ON ghgen_pool(issued_to);

-- Per-key daily claim buckets.
CREATE TABLE IF NOT EXISTS ghgen_buckets (
    key TEXT PRIMARY KEY,
    day_bucket INTEGER NOT NULL,
    count INTEGER NOT NULL DEFAULT 0,
    last_claim_at INTEGER NOT NULL DEFAULT 0
);

-- Claim ledger (who got what, when).
CREATE TABLE IF NOT EXISTS ghgen_claims (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key TEXT NOT NULL,
    user_id INTEGER NOT NULL,
    pool_id INTEGER NOT NULL,
    region TEXT,
    claimed_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ghgen_claims_user ON ghgen_claims(user_id);

-- Rate-limit ledger (IP x action x timestamp window).
CREATE TABLE IF NOT EXISTS ghgen_ratelimit (
    ip TEXT NOT NULL,
    action TEXT NOT NULL,
    ts INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ratelimit_ip_action_ts ON ghgen_ratelimit(ip, action, ts);

-- Generated accounts (bot pipeline: pending|running|success|fail).
CREATE TABLE IF NOT EXISTS ghgen_accounts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    roblox_username TEXT,
    roblox_password TEXT,
    cookie TEXT,
    country TEXT,
    city TEXT,
    ip TEXT,
    status TEXT NOT NULL DEFAULT 'pending',
    reason TEXT,
    created_at INTEGER NOT NULL,
    finished_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_ghgen_accounts_user ON ghgen_accounts(user_id);
CREATE INDEX IF NOT EXISTS idx_ghgen_accounts_status ON ghgen_accounts(status);

-- Audit log.
CREATE TABLE IF NOT EXISTS ghgen_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    action TEXT NOT NULL,
    meta TEXT,
    ip TEXT,
    created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ghgen_log_user ON ghgen_log(user_id);
