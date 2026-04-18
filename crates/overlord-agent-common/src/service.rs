use anyhow::Result;
use async_trait::async_trait;
use serde_json::Value;
use uuid::Uuid;

use crate::types::{
    AgentNetworkReport, ConfigUpdate, IndexerStats, PopularHash, Protocol, SearchJob, SnoopEntry,
};

#[async_trait]
pub trait IndexerService: Send + Sync + 'static {
    fn protocol(&self) -> Protocol;
    fn version(&self) -> &str;
    fn indexer_id(&self) -> Uuid;

    async fn start(&self) -> Result<()>;
    async fn stop(&self) -> Result<()>;
    async fn search(&self, job: SearchJob) -> Result<()>;
    async fn cancel_search(&self, job_id: Uuid) -> Result<()>;
    async fn stats(&self) -> Result<IndexerStats>;
    async fn apply_config(&self, config: ConfigUpdate) -> Result<()>;

    async fn interfaces(&self) -> Result<AgentNetworkReport> {
        anyhow::bail!("interfaces are not implemented for this agent")
    }

    async fn enrich(&self, _payload: Value) -> Result<()> {
        anyhow::bail!("enrich is not implemented for this agent")
    }

    async fn seed_popular(&self, _hashes: Vec<PopularHash>) -> Result<()> {
        anyhow::bail!("seed_popular is not implemented for this agent")
    }

    async fn ingest_local_file(&self, _payload: Value) -> Result<Value> {
        anyhow::bail!("ingest_local_file is not implemented for this agent")
    }

    async fn flush_snoop(&self) -> Result<Vec<SnoopEntry>> {
        Ok(Vec::new())
    }
}
