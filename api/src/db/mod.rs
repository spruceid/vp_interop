use anyhow::{bail, Result};
use async_trait::async_trait;
use isomdl180137::verify::UnattendedSessionManager;
use oidc4vp::mdl_request::RequestObject;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

// #[cfg(target_arch = "wasm32")]
pub mod cf;

const KV_NAMESPACE: &str = "JWT_VC_INTEROP";

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct StartedInfo {
    pub nonce: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct OnlinePresentmentState {
    pub unattended_session_manager: UnattendedSessionManager,
    pub request: RequestObject,
    pub presentation_type: String,
    pub verifier_id: String,
    pub protocol: String,
    pub transaction_id: String,
    #[serde(with = "time::serde::rfc3339")]
    pub timestamp: OffsetDateTime,
    pub complete: bool,
    pub scenario: String,
    pub v_data_1: Check,
    pub v_data_2: Check,
    pub v_data_3: Check,
    pub v_sec_1: Check,
    pub v_sec_2: Check,
    pub v_sec_3: Check,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Check {
    timestamp: OffsetDateTime,
    result: Option<bool>,
}

impl Check {
    fn to_log(&self) -> (i64, &'static str) {
        (
            self.timestamp.unix_timestamp(),
            self.result
                .map(|r| if r { "OK" } else { "Failed" })
                .unwrap_or("Skipped"),
        )
    }
}

impl From<Option<bool>> for Check {
    fn from(result: Option<bool>) -> Self {
        Self {
            result,
            timestamp: OffsetDateTime::now_utc(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum VPProgress {
    Started(StartedInfo),
    OPState(OnlinePresentmentState),
    Failed(serde_json::Value),
    Done(serde_json::Value),
}

impl OnlinePresentmentState {
    pub fn status(&self) -> Result<String> {
        let Self {
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
        } = self;
        let started = timestamp.unix_timestamp();
        let v_data_1 = v_data_1.to_log();
        let v_data_2 = v_data_2.to_log();
        let v_data_3 = v_data_3.to_log();
        let v_sec_1 = v_sec_1.to_log();
        let v_sec_2 = v_sec_2.to_log();
        let v_sec_3 = v_sec_3.to_log();
        let mut checks = [
            (v_data_1.0, v_data_1.1, "V_DATA_1"),
            (v_data_2.0, v_data_2.1, "V_DATA_2"),
            (v_data_3.0, v_data_3.1, "V_DATA_3"),
            (v_sec_1.0, v_sec_1.1, "V_SEC_1"),
            (v_sec_2.0, v_sec_2.1, "V_SEC_2"),
            (v_sec_3.0, v_sec_3.1, "V_SEC_3"),
        ];
        checks.sort_by(|a, b| a.0.cmp(&b.0));
        let checks = checks
            .into_iter()
            .map(|(ts, res, name)| format!("[{ts}] Check: {name}: {res}"))
            .collect::<Vec<String>>()
            .join("\n");

        Ok(format!(
            r#"
Verifier: {verifier_id}
Protocol: {protocol}
Transaction: {transaction_id}
Started: {started}
Scenario: {scenario}
{checks}
            "#
        ))
    }
}

impl VPProgress {
    pub fn status(&self) -> Result<String> {
        let Self::OPState(opstate) = self else {
            bail!("unexpected state")
        };
        opstate.status()
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
