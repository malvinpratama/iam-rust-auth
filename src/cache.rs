//! Optional Redis layer shared across auth replicas: an access-token denylist
//! (revoked jti) and a per-user permission cache. When REDIS_URL is unset or
//! unreachable every method is a no-op/miss and callers fall back to Postgres.

use redis::AsyncCommands;

const PERMS_TTL_SECS: u64 = 60;

#[derive(Clone)]
pub struct Cache {
    conn: Option<redis::aio::ConnectionManager>,
}

impl Cache {
    pub async fn new(url: &str) -> Self {
        if url.is_empty() {
            return Self { conn: None };
        }
        match redis::Client::open(url) {
            Ok(client) => match redis::aio::ConnectionManager::new(client).await {
                Ok(cm) => Self { conn: Some(cm) },
                Err(_) => Self { conn: None },
            },
            Err(_) => Self { conn: None },
        }
    }

    pub fn enabled(&self) -> bool {
        self.conn.is_some()
    }

    /// Denylist a revoked access-token jti for ttl_secs.
    pub async fn deny(&self, jti: &str, ttl_secs: i64) {
        if jti.is_empty() || ttl_secs <= 0 {
            return;
        }
        if let Some(cm) = &self.conn {
            let mut c = cm.clone();
            let _: Result<(), _> = c.set_ex(format!("denylist:{jti}"), 1, ttl_secs as u64).await;
        }
    }

    /// Some(true/false) when Redis answered; None means "ask Postgres".
    pub async fn is_denied(&self, jti: &str) -> Option<bool> {
        if jti.is_empty() {
            return None;
        }
        let cm = self.conn.as_ref()?;
        let mut c = cm.clone();
        c.exists::<_, bool>(format!("denylist:{jti}")).await.ok()
    }

    pub async fn get_perms(&self, tenant: &str, project: &str, user_id: &str) -> Option<Vec<String>> {
        let cm = self.conn.as_ref()?;
        let mut c = cm.clone();
        let v: String = c.get(perms_key(tenant, project, user_id)).await.ok()?;
        serde_json::from_str(&v).ok()
    }

    pub async fn set_perms(&self, tenant: &str, project: &str, user_id: &str, perms: &[String]) {
        if let Some(cm) = &self.conn {
            if let Ok(json) = serde_json::to_string(perms) {
                let mut c = cm.clone();
                let _: Result<(), _> =
                    c.set_ex(perms_key(tenant, project, user_id), json, PERMS_TTL_SECS).await;
            }
        }
    }

    /// Drop ALL of a user's cached permission entries across every tenant/project
    /// (after a role change), via a SCAN+DEL over perms:*:*:<user>.
    pub async fn invalidate_perms(&self, user_id: &str) {
        if let Some(cm) = &self.conn {
            let mut c = cm.clone();
            let pattern = format!("perms:*:*:{user_id}");
            let mut cursor: u64 = 0;
            loop {
                let res: Result<(u64, Vec<String>), _> = redis::cmd("SCAN")
                    .arg(cursor)
                    .arg("MATCH")
                    .arg(&pattern)
                    .arg("COUNT")
                    .arg(100)
                    .query_async(&mut c)
                    .await;
                let (next, keys) = match res {
                    Ok(v) => v,
                    Err(_) => return,
                };
                if !keys.is_empty() {
                    let _: Result<(), _> = c.del(keys).await;
                }
                if next == 0 {
                    break;
                }
                cursor = next;
            }
        }
    }
}

/// M6.3: scope a user's cached permissions to the active tenant/project, since
/// permissions differ per tenant. Empty project (tenant-wide) → sentinel "-".
fn perms_key(tenant: &str, project: &str, user_id: &str) -> String {
    let t = if tenant.is_empty() { "-" } else { tenant };
    let p = if project.is_empty() { "-" } else { project };
    format!("perms:{t}:{p}:{user_id}")
}
