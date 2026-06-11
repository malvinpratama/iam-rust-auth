-- Refresh-token rotation grace: tell a token revoked by *rotation* (it has a
-- successor) apart from one revoked by *logout* (no successor), so a concurrent
-- re-presentation within a short grace window is treated as the benign parallel-
-- refresh race (re-issue) instead of theft (whole-family wipe). replaced_by
-- holds the hash of the successor token.
ALTER TABLE refresh_tokens ADD COLUMN IF NOT EXISTS replaced_by TEXT;
