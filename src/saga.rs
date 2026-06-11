//! Registration compensation: when the user service gives up creating a profile
//! (ProfileCreationFailed), auth soft-deletes the half-created identity so
//! registration leaves no orphans.

use async_nats::jetstream::{
    self,
    consumer::{pull, AckPolicy, PullConsumer},
    AckKind,
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
                Ok(ev) => match Uuid::parse_str(&ev.user_id) {
                    Ok(uid) => match repo.soft_delete_user(uid).await {
                        Ok(_) => {
                            let _ = repo
                                .insert_audit("system", "saga", "saga.profile_failed.compensated", &ev.user_id, &ev.reason)
                                .await;
                            let _ = msg.ack().await;
                            tracing::warn!(user_id = %ev.user_id, reason = %ev.reason, "compensated half-created identity (soft-deleted)");
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "compensation failed; will retry");
                            let _ = msg.ack_with(AckKind::Nak(None)).await;
                        }
                    },
                    Err(_) => {
                        let _ = msg.ack().await;
                    }
                },
                Err(e) => {
                    tracing::warn!(error = %e, "bad ProfileCreationFailed payload");
                    let _ = msg.ack().await;
                }
            }
        }
    }
}
