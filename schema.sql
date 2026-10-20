CREATE TABLE IF NOT EXISTS ofauth_tokens (user_id text PRIMARY KEY, tokens jsonb NOT NULL);
CREATE TABLE IF NOT EXISTS ofauth_pending (state text PRIMARY KEY, pending jsonb NOT NULL, expires_at timestamptz NOT NULL);
CREATE TABLE IF NOT EXISTS app_selection (user_key text PRIMARY KEY, linked_account_id text NOT NULL);
CREATE TABLE IF NOT EXISTS app_reconnect (state text PRIMARY KEY, session_id text NOT NULL, user_key text NOT NULL, linked_account_id text NOT NULL, expires_at timestamptz NOT NULL);
