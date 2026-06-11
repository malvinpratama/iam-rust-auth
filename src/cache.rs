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

    pub async fn get_perms(&self, user_id: &str) -> Option<Vec<String>> {
        let cm = self.conn.as_ref()?;
        let mut c = cm.clone();
        let v: String = c.get(format!("perms:{user_id}")).await.ok()?;
        serde_json::from_str(&v).ok()
    }

    pub async fn set_perms(&self, user_id: &str, perms: &[String]) {
        if let Some(cm) = &self.conn {
            if let Ok(json) = serde_json::to_string(perms) {
                let mut c = cm.clone();
                let _: Result<(), _> = c.set_ex(format!("perms:{user_id}"), json, PERMS_TTL_SECS).await;
            }
        }
    }

    pub async fn invalidate_perms(&self, user_id: &str) {
        if let Some(cm) = &self.conn {
            let mut c = cm.clone();
            let _: Result<(), _> = c.del(format!("perms:{user_id}")).await;
        }
    }
}
