CREATE TABLE IF NOT EXISTS identity_events (
  id text PRIMARY KEY,
  source text NOT NULL CHECK (source IN ('keycloak.user', 'keycloak.admin')),
  realm text NOT NULL,
  event_type text NOT NULL,
  occurred_at timestamptz NOT NULL,
  received_at timestamptz NOT NULL DEFAULT now(),
  actor_id text,
  session_id text,
  client_id text,
  ip_address text,
  resource text,
  outcome text NOT NULL CHECK (outcome IN ('success', 'failure')),
  details jsonb NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS identity_events_time ON identity_events (occurred_at DESC);
CREATE INDEX IF NOT EXISTS identity_events_actor ON identity_events (actor_id, occurred_at DESC);
CREATE TABLE IF NOT EXISTS connector_state (
  source text PRIMARY KEY,
  cursor_at timestamptz NOT NULL,
  last_success_at timestamptz,
  status text NOT NULL,
  last_error text
);
CREATE TABLE IF NOT EXISTS console_sessions (
  token_hash text PRIMARY KEY,
  subject text NOT NULL,
  username text NOT NULL,
  encrypted_access_token text NOT NULL,
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
