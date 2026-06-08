//! Outbox relay: drains pending domain events to NATS JetStream.
//!
//! Publishes each unpublished outbox row with the row id as the NATS message id
//! (server-side dedupe collapses a double-publish after a crash), then marks the
//! row published. Delivery is at-least-once.

use std::time::Duration;

use async_nats::jetstream::Context;

use crate::repo::Repo;

/// Poll the outbox forever, publishing pending events. Run in its own task.
pub async fn run(repo: Repo, js: Context) {
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    loop {
        interval.tick().await;
        if let Err(e) = drain(&repo, &js).await {
            tracing::warn!(error = %e, "outbox drain failed");
        }
    }
}

async fn drain(repo: &Repo, js: &Context) -> anyhow::Result<()> {
    let rows = repo.fetch_unpublished_outbox(100).await?;
    for row in rows {
        let subject = format!("{}{}", common::events::SUBJECT_PREFIX, row.event_type);
        let mut headers = async_nats::HeaderMap::new();
        headers.insert("Nats-Msg-Id", row.id.to_string().as_str());
        js.publish_with_headers(subject, headers, row.payload.into_bytes().into())
            .await?
            .await?;
        repo.mark_outbox_published(row.id).await?;
        tracing::info!(id = %row.id, "event published");
    }
    Ok(())
}
