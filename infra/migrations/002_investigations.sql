CREATE TABLE IF NOT EXISTS demo_identities (
  identity_id text PRIMARY KEY, username text NOT NULL UNIQUE,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS investigations (
  id uuid PRIMARY KEY, requested_by text NOT NULL, identity_id text NOT NULL,
  title text NOT NULL, mode text NOT NULL CHECK(mode IN ('replay','live')),
  engine text NOT NULL CHECK(engine IN ('rehearsal','openai')),
  status text NOT NULL DEFAULT 'QUEUED' CHECK(status IN ('QUEUED','RUNNING','COMPLETED','FAILED','CANCELLED','LIMIT_REACHED')),
  run jsonb NOT NULL, snapshot jsonb, detection jsonb NOT NULL,
  report jsonb, agents jsonb NOT NULL DEFAULT '{}', error text,
  mcp_calls integer NOT NULL DEFAULT 0, created_at timestamptz NOT NULL DEFAULT now(),
  started_at timestamptz, finished_at timestamptz, lease_until timestamptz,
  cancel_requested boolean NOT NULL DEFAULT false
);
CREATE INDEX IF NOT EXISTS investigation_queue ON investigations(status,created_at);
CREATE TABLE IF NOT EXISTS investigation_steps (
  id bigserial PRIMARY KEY, investigation_id uuid NOT NULL REFERENCES investigations(id),
  agent text NOT NULL, kind text NOT NULL, summary text NOT NULL,
  payload jsonb NOT NULL DEFAULT '{}', created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS response_actions (
  id uuid PRIMARY KEY, investigation_id uuid NOT NULL UNIQUE REFERENCES investigations(id),
  type text NOT NULL CHECK(type='REVOKE_SESSION'), target_session text NOT NULL,
  mode text NOT NULL CHECK(mode IN ('replay','live')),
  status text NOT NULL DEFAULT 'PENDING' CHECK(status IN ('PENDING','EXECUTING','VERIFIED','REJECTED','FAILED')),
  reason text NOT NULL, approved_by text, decided_at timestamptz,
  expires_at timestamptz NOT NULL, verification jsonb, created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS investigation_audit (
  id bigserial PRIMARY KEY, investigation_id uuid NOT NULL REFERENCES investigations(id),
  actor text NOT NULL, action text NOT NULL, details jsonb NOT NULL DEFAULT '{}',
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS demo_session_probes (
  session_id text PRIMARY KEY, identity_id text NOT NULL REFERENCES demo_identities(identity_id),
  encrypted_token text NOT NULL, expires_at timestamptz NOT NULL
);
CREATE TABLE IF NOT EXISTS runtime_health (name text PRIMARY KEY, updated_at timestamptz NOT NULL, details jsonb NOT NULL DEFAULT '{}');
