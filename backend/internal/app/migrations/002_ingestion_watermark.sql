-- Increasing retention must not reopen periods whose raw deduplication records were deleted.
ALTER TABLE organizations ADD COLUMN ingest_not_before timestamptz NOT NULL DEFAULT '1970-01-01T00:00:00Z';
