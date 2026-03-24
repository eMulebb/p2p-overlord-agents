use anyhow::{Context, Result};
use reqwest::Url;

use crate::types::{
    AgentInterfacesView, AgentNetworkReport, ConfigUpdate, HarvestReplayRecord,
    IndexerRegistration, IndexerStats, PopularHash, RegisterRequest, RegistrationResponse,
    ResultBatch, SearchCancelRequest, SearchEvent, SearchJob, SearchKind, SnoopEntry,
    SnoopObservation,
};

#[derive(Clone)]
pub struct CoordinatorClient {
    base_url: Url,
    http: reqwest::Client,
}

impl CoordinatorClient {
    pub fn new(base_url: &str) -> Result<Self> {
        Ok(Self {
            base_url: Url::parse(base_url)
                .with_context(|| format!("invalid coordinator base url: {base_url}"))?,
            http: reqwest::Client::new(),
        })
    }

    pub async fn register(&self, payload: &RegisterRequest) -> Result<IndexerRegistration> {
        let url = self.base_url.join("/api/internal/register")?;
        let response = self
            .http
            .post(url)
            .json(payload)
            .send()
            .await?
            .error_for_status()?
            .json::<RegistrationResponse>()
            .await?;
        Ok(response.registered)
    }

    pub async fn post_results(&self, batch: &ResultBatch) -> Result<()> {
        let url = self.base_url.join("/api/internal/results")?;
        self.http
            .post(url)
            .json(batch)
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    pub async fn post_search_event(&self, event: &SearchEvent) -> Result<()> {
        let url = self.base_url.join("/api/internal/search-events")?;
        self.http
            .post(url)
            .json(event)
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    pub async fn dispatch_search(&self, job: &SearchJob) -> Result<()> {
        let url = self.base_url.join("/api/search")?;
        let payload = match job.kind {
            SearchKind::Keyword => serde_json::json!({
                "protocol": job.protocol,
                "kind": "keyword",
                "query": job.query,
            }),
            SearchKind::Source | SearchKind::Notes => serde_json::json!({
                "protocol": job.protocol,
                "kind": job.kind,
                "file_hash": job.file_hash,
                "file_size": job.file_size,
            }),
        };
        self.http
            .post(url)
            .json(&payload)
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    pub async fn cancel_internal_search(&self, payload: &SearchCancelRequest) -> Result<()> {
        let url = self.base_url.join("/api/internal/search/cancel")?;
        self.http
            .post(url)
            .json(payload)
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    pub async fn flush_snoop(
        &self,
        indexer_id: uuid::Uuid,
        entries: &[SnoopEntry],
        observations: &[SnoopObservation],
    ) -> Result<()> {
        let url = self.base_url.join("/api/internal/snoop-flush")?;
        self.http
            .post(url)
            .json(&serde_json::json!({
                "indexer_id": indexer_id,
                "entries": entries,
                "observations": observations,
            }))
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    pub async fn restore_snoop(&self, indexer_id: uuid::Uuid) -> Result<Vec<SnoopEntry>> {
        let url = self
            .base_url
            .join(&format!("/api/internal/snoop-restore/{indexer_id}"))?;
        Ok(self
            .http
            .get(url)
            .send()
            .await?
            .error_for_status()?
            .json::<Vec<SnoopEntry>>()
            .await?)
    }

    pub async fn popular_hashes(&self) -> Result<Vec<PopularHash>> {
        let url = self.base_url.join("/api/internal/popular-hashes")?;
        Ok(self
            .http
            .get(url)
            .send()
            .await?
            .error_for_status()?
            .json::<Vec<PopularHash>>()
            .await?)
    }

    pub async fn post_harvest_replay(&self, payload: &HarvestReplayRecord) -> Result<()> {
        let url = self.base_url.join("/api/internal/harvest-replays")?;
        self.http
            .post(url)
            .json(payload)
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    pub async fn stats(&self) -> Result<IndexerStats> {
        let url = self.base_url.join("/api/internal/stats")?;
        Ok(self
            .http
            .get(url)
            .send()
            .await?
            .error_for_status()?
            .json::<IndexerStats>()
            .await?)
    }

    pub async fn interfaces(&self) -> Result<AgentNetworkReport> {
        let url = self.base_url.join("/api/internal/interfaces")?;
        Ok(self
            .http
            .get(url)
            .send()
            .await?
            .error_for_status()?
            .json::<AgentNetworkReport>()
            .await?)
    }

    pub async fn agent_interfaces_view(
        &self,
        indexer_id: uuid::Uuid,
    ) -> Result<AgentInterfacesView> {
        let url = self
            .base_url
            .join(&format!("/api/agents/{indexer_id}/interfaces"))?;
        Ok(self
            .http
            .get(url)
            .send()
            .await?
            .error_for_status()?
            .json::<AgentInterfacesView>()
            .await?)
    }

    pub async fn apply_config_update(&self, payload: &ConfigUpdate) -> Result<()> {
        let url = self.base_url.join("/api/internal/config-update")?;
        self.http
            .post(url)
            .json(payload)
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }
}
