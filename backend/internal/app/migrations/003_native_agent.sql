ALTER TABLE devices ADD COLUMN health jsonb NOT NULL DEFAULT '{}';
ALTER TABLE devices ADD COLUMN health_received_at timestamptz;
ALTER TABLE devices ADD COLUMN loss_counters jsonb NOT NULL DEFAULT '{}';
ALTER TABLE events ADD COLUMN wire_version integer NOT NULL DEFAULT 1 CHECK (wire_version IN (1,2));
