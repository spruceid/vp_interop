use anyhow::{anyhow, Result};
use async_trait::async_trait;
use uuid::Uuid;
use worker::RouteContext;

use super::{DBClient, VPProgress, KV_NAMESPACE};

pub struct CFDBClient {
    pub ctx: RouteContext<()>,
}

// #[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
// #[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[async_trait(?Send)]
impl DBClient for CFDBClient {
    async fn get_vp(&self, id: Uuid) -> Result<Option<VPProgress>> {
        self.ctx
            .kv(KV_NAMESPACE)
            .map_err(|e| anyhow!("Failed to get KV store: {}", e))?
            .get(&id.to_string())
            .json()
            .await
            .map_err(|e| anyhow!("Failed to get KV: {}", e))
    }

    async fn put_vp(&mut self, id: Uuid, info: VPProgress) -> Result<()> {
        self.ctx
            .kv(KV_NAMESPACE)
            .map_err(|e| anyhow!("Failed to get KV store: {}", e))?
            .put(
                &id.to_string(),
                serde_json::to_string(&info)
                    .map_err(|e| anyhow!("Failed to serialize vp info: {}", e))?,
            )
            .map_err(|e| anyhow!("Failed to build KV put: {}", e))?
            .execute()
            .await
            .map_err(|e| anyhow!("Failed to put KV: {}", e))?;
        Ok(())
    }
}
