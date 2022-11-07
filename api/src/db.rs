use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use worker::RouteContext;

const KV_NAMESPACE: &str = "JWT_VC_INTEROP";
const TTL: u64 = 300; // 5min

#[derive(Serialize, Deserialize)]
pub enum VPProgress {
    Started { nonce: String },
    Done,
}

pub struct DBClient {
    pub ctx: RouteContext<()>,
}

impl DBClient {
    pub async fn get_vp(&self, id: Uuid) -> Result<Option<VPProgress>> {
        self.ctx
            .kv(KV_NAMESPACE)
            .map_err(|e| anyhow!("Failed to get KV store: {}", e))?
            .get(&id.to_string())
            .json()
            .await
            .map_err(|e| anyhow!("Failed to get KV: {}", e))
    }

    pub async fn put_vp(&self, id: Uuid, info: VPProgress) -> Result<()> {
        self.ctx
            .kv(KV_NAMESPACE)
            .map_err(|e| anyhow!("Failed to get KV store: {}", e))?
            .put(
                &id.to_string(),
                serde_json::to_string(&info)
                    .map_err(|e| anyhow!("Failed to serialize vp info: {}", e))?,
            )
            .map_err(|e| anyhow!("Failed to build KV put: {}", e))?
            .expiration_ttl(TTL)
            .execute()
            .await
            .map_err(|e| anyhow!("Failed to put KV: {}", e))?;
        Ok(())
    }
}
