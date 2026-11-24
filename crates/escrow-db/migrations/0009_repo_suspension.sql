ALTER TABLE repos ADD COLUMN suspended_at TIMESTAMPTZ;
CREATE INDEX repos_suspended ON repos (suspended_at) WHERE suspended_at IS NOT NULL;
