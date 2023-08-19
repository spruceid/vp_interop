use anyhow::{bail, Result};
use async_trait::async_trait;
use isomdl180137::verify::UnattendedSessionManager;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::CustomError;

// #[cfg(target_arch = "wasm32")]
pub mod cf;

const KV_NAMESPACE: &str = "JWT_VC_INTEROP";
const TTL: u64 = 300; // 5min

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct StartedInfo {
    pub nonce: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct OnlinePresentmentState {
    pub unattended_session_manager: UnattendedSessionManager,
    pub verifier_id: String,
    pub protocol: String,
    pub transaction_id: String,
    #[serde(with = "time::serde::rfc3339")]
    pub timestamp: OffsetDateTime,
    pub complete: bool,
    pub scenario: String,
    pub v_data_1: Option<bool>,
    pub v_data_2: Option<bool>,
    pub v_data_3: Option<bool>,
    pub v_sec_1: Option<bool>,
    pub v_sec_2: Option<bool>,
    pub v_sec_3: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum VPProgress {
    Started(StartedInfo),
    OPState(OnlinePresentmentState),
    Failed(serde_json::Value),
    Done(serde_json::Value),
}

impl VPProgress {
    pub fn to_html(&self) -> Result<String, CustomError> {
        let status = self
            .status()
            .map_err(|e| CustomError::InternalError(e.to_string()))?;
        Ok(format!("<p>{status}</p>"))
    }

    pub fn status(&self) -> Result<String> {
        let Self::OPState(OnlinePresentmentState {
            verifier_id,
            protocol,
            transaction_id,
            timestamp,
            scenario,
            v_data_1,
            v_data_2,
            v_data_3,
            v_sec_1,
            v_sec_2,
            v_sec_3,
            ..
        }) = self
        else { bail!("unexpected state") };
        let started = timestamp.unix_timestamp();
        let v_data_1 = v_data_1
            .map(|r| if r { "OK" } else { "Failed" })
            .unwrap_or("Skipped");
        let v_data_2 = v_data_2
            .map(|r| if r { "OK" } else { "Failed" })
            .unwrap_or("Skipped");
        let v_data_3 = v_data_3
            .map(|r| if r { "OK" } else { "Failed" })
            .unwrap_or("Skipped");
        let v_sec_1 = v_sec_1
            .map(|r| if r { "OK" } else { "Failed" })
            .unwrap_or("Skipped");
        let v_sec_2 = v_sec_2
            .map(|r| if r { "OK" } else { "Failed" })
            .unwrap_or("Skipped");
        let v_sec_3 = v_sec_3
            .map(|r| if r { "OK" } else { "Failed" })
            .unwrap_or("Skipped");
        Ok(format!(
            r#"
Verifier: {verifier_id}
Protocol: {protocol}
Transaction: {transaction_id}
Started: {started}
Scenario: {scenario}
[ts] Check: V_DATA_1: {v_data_1}
[ts] Check: V_DATA_2: {v_data_2}
[ts] Check: V_DATA_3: {v_data_3}
[ts] Check: V_SEC_1: {v_sec_1}
[ts] Check: V_SEC_2: {v_sec_2}
[ts] Check: V_SEC_3: {v_sec_3}
            "#
        ))
    }
}

// #[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
// #[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[async_trait(?Send)]
pub trait DBClient {
    async fn get_vp(&self, id: Uuid) -> Result<Option<VPProgress>>;
    async fn put_vp(&mut self, id: Uuid, info: VPProgress) -> Result<()>;
}

#[cfg(test)]
pub(crate) mod tests {
    use std::collections::HashMap;

    use super::*;

    pub struct MemoryDBClient {
        store: HashMap<Uuid, VPProgress>,
    }

    impl MemoryDBClient {
        pub fn new() -> Self {
            Self {
                store: HashMap::new(),
            }
        }
    }

    #[async_trait(?Send)]
    impl DBClient for MemoryDBClient {
        async fn get_vp(&self, id: Uuid) -> Result<Option<VPProgress>> {
            Ok(self.store.get(&id).cloned())
        }
        async fn put_vp(&mut self, id: Uuid, info: VPProgress) -> Result<()> {
            self.store.insert(id, info);
            Ok(())
        }
    }
}
