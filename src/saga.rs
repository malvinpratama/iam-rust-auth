//! Handles permanently-failed profile creation. When the user service gives up
//! (ProfileCreationFailed), auth records the incident for ops visibility but
//! keeps the identity active — the profile is recreated by lazy-heal on the next
//! GET /users/me, so the user is never locked out (forward recovery, not a
//! destructive rollback).

use async_nats::jetstream::{
    self,
    consumer::{pull, AckPolicy, PullConsumer},
};
use futures::StreamExt;
use uuid::Uuid;

use crate::repo::Repo;

/// Subscribe to profile-creation-failed events and compensate. Spawns a task.
pub async fn run(repo: Repo, js: jetstream::Context) -> anyhow::Result<()> {
    let stream = js
        .get_stream(common::events::STREAM)
        .await
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;
    let consumer = stream
        .get_or_create_consumer(
            "auth-saga-profile-failed",
            pull::Config {
                durable_name: Some("auth-saga-profile-failed".to_string()),
                filter_subject: common::events::SUBJECT_PROFILE_FAILED.to_string(),
                ack_policy: AckPolicy::Explicit,
                ..Default::default()
            },
        )
        .await
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;
    tokio::spawn(async move { consume(repo, consumer).await });
    tracing::info!("saga compensator started");
    Ok(())
}

async fn consume(repo: Repo, consumer: PullConsumer) {
    loop {
        let mut messages = match consumer.messages().await {
            Ok(m) => m,
            Err(e) => {
                tracing::warn!(error = %e, "saga messages stream error");
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                continue;
            }
        };
        while let Some(item) = messages.next().await {
            let msg = match item {
                Ok(m) => m,
                Err(e) => {
                    tracing::warn!(error = %e, "saga recv error");
                    break;
                }
            };
            match serde_json::from_slice::<common::events::ProfileCreationFailed>(&msg.payload) {
                Ok(ev) => {
                    if Uuid::parse_str(&ev.user_id).is_ok() {
                        // Forward recovery, not rollback: keep the identity
                        // active and record the failure. The profile is recreated
                        // by lazy-heal on the next GET /users/me.
                        let _ = repo
                            .insert_audit("system", "saga", "profile.creation_failed", &ev.user_id, &ev.reason)
                            .await;
                        tracing::warn!(user_id = %ev.user_id, reason = %ev.reason, "profile creation failed permanently; identity kept active, profile will self-heal on next /users/me read");
                    }
                    let _ = msg.ack().await;
                }
                Err(e) => {
                    tracing::warn!(error = %e, "bad ProfileCreationFailed payload");
                    let _ = msg.ack().await;
                }
            }
        }
    }
}
