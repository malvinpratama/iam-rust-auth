-- Transactional outbox: auth records domain events in the SAME transaction as
-- the write that produced them, and a relay publishes unpublished rows to NATS
-- JetStream (at-least-once delivery without a distributed transaction).

CREATE TABLE IF NOT EXISTS outbox (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    aggregate_id UUID        NOT NULL,            -- the user_id the event is about
    event_type   TEXT        NOT NULL,            -- 'user.registered' | 'user.deleted'
    payload      JSONB       NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    published_at TIMESTAMPTZ                      -- NULL until the relay publishes it
);

CREATE INDEX IF NOT EXISTS idx_outbox_unpublished ON outbox (created_at) WHERE published_at IS NULL;
