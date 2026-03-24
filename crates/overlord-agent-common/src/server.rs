use std::{net::SocketAddr, sync::Arc, time::Duration};

use anyhow::{Context, Result};
use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
};
use serde_json::Value;
use tokio::{sync::oneshot, task::JoinHandle, time::timeout};
use tracing::warn;

use crate::{
    service::IndexerService,
    types::{ConfigUpdate, PopularHash, SearchCancelRequest, SearchJob},
};

struct AppState<S>
where
    S: IndexerService,
{
    service: Arc<S>,
}

impl<S> Clone for AppState<S>
where
    S: IndexerService,
{
    fn clone(&self) -> Self {
        Self {
            service: Arc::clone(&self.service),
        }
    }
}

pub struct IndexerServer<S>
where
    S: IndexerService,
{
    service: Arc<S>,
}

pub struct RunningIndexerServer {
    local_addr: SocketAddr,
    shutdown_tx: Option<oneshot::Sender<()>>,
    task: JoinHandle<Result<()>>,
}

impl<S> IndexerServer<S>
where
    S: IndexerService,
{
    pub fn new(service: Arc<S>) -> Self {
        Self { service }
    }

    pub async fn spawn(self, bind_addr: SocketAddr) -> Result<RunningIndexerServer> {
        let state = AppState {
            service: self.service,
        };
        let app = Router::new()
            .route("/api/internal/health", get(get_health::<S>))
            .route("/api/internal/stats", get(get_stats::<S>))
            .route("/api/internal/interfaces", get(get_interfaces::<S>))
            .route("/api/internal/search", post(post_search::<S>))
            .route("/api/internal/search/cancel", post(post_cancel_search::<S>))
            .route("/api/internal/enrich", post(post_enrich::<S>))
            .route("/api/internal/seed-popular", post(post_seed_popular::<S>))
            .route("/api/internal/config-update", post(post_config_update::<S>))
            .with_state(state);

        let listener = tokio::net::TcpListener::bind(bind_addr).await?;
        let local_addr = listener.local_addr()?;
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let task = tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    let _ = shutdown_rx.await;
                })
                .await
                .context("indexer control server exited with error")
        });

        Ok(RunningIndexerServer {
            local_addr,
            shutdown_tx: Some(shutdown_tx),
            task,
        })
    }

    pub async fn serve(self, bind_addr: SocketAddr) -> Result<()> {
        let server = self.spawn(bind_addr).await?;
        server.wait().await
    }
}

impl RunningIndexerServer {
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub async fn shutdown(mut self) -> Result<()> {
        if let Some(shutdown_tx) = self.shutdown_tx.take() {
            let _ = shutdown_tx.send(());
        }
        match timeout(Duration::from_secs(2), &mut self.task).await {
            Ok(result) => result.context("failed to join indexer control server task")?,
            Err(_) => {
                warn!("indexer control server shutdown timed out; aborting lingering connections");
                self.task.abort();
                let _ = self.task.await;
                Ok(())
            }
        }
    }

    pub async fn wait(self) -> Result<()> {
        self.task
            .await
            .context("failed to join indexer control server task")?
    }
}

async fn get_health<S>(State(state): State<AppState<S>>) -> impl IntoResponse
where
    S: IndexerService,
{
    let payload = serde_json::json!({
        "ok": true,
        "protocol": state.service.protocol(),
        "indexer_id": state.service.indexer_id(),
        "version": state.service.version(),
    });
    (StatusCode::OK, Json(payload))
}

async fn get_stats<S>(State(state): State<AppState<S>>) -> impl IntoResponse
where
    S: IndexerService,
{
    match state.service.stats().await {
        Ok(stats) => (StatusCode::OK, Json(serde_json::json!(stats))).into_response(),
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": error.to_string() })),
        )
            .into_response(),
    }
}

async fn get_interfaces<S>(State(state): State<AppState<S>>) -> impl IntoResponse
where
    S: IndexerService,
{
    match state.service.interfaces().await {
        Ok(report) => (StatusCode::OK, Json(serde_json::json!(report))).into_response(),
        Err(error) => (
            StatusCode::NOT_IMPLEMENTED,
            Json(serde_json::json!({ "error": error.to_string() })),
        )
            .into_response(),
    }
}

async fn post_search<S>(
    State(state): State<AppState<S>>,
    Json(job): Json<SearchJob>,
) -> impl IntoResponse
where
    S: IndexerService,
{
    match state.service.search(job).await {
        Ok(()) => StatusCode::ACCEPTED.into_response(),
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": error.to_string() })),
        )
            .into_response(),
    }
}

async fn post_cancel_search<S>(
    State(state): State<AppState<S>>,
    Json(payload): Json<SearchCancelRequest>,
) -> impl IntoResponse
where
    S: IndexerService,
{
    match state.service.cancel_search(payload.job_id).await {
        Ok(()) => StatusCode::ACCEPTED.into_response(),
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": error.to_string() })),
        )
            .into_response(),
    }
}

async fn post_enrich<S>(
    State(state): State<AppState<S>>,
    Json(payload): Json<Value>,
) -> impl IntoResponse
where
    S: IndexerService,
{
    match state.service.enrich(payload).await {
        Ok(()) => StatusCode::ACCEPTED.into_response(),
        Err(error) => (
            StatusCode::NOT_IMPLEMENTED,
            Json(serde_json::json!({ "error": error.to_string() })),
        )
            .into_response(),
    }
}

async fn post_seed_popular<S>(
    State(state): State<AppState<S>>,
    Json(payload): Json<Vec<PopularHash>>,
) -> impl IntoResponse
where
    S: IndexerService,
{
    match state.service.seed_popular(payload).await {
        Ok(()) => StatusCode::ACCEPTED.into_response(),
        Err(error) => (
            StatusCode::NOT_IMPLEMENTED,
            Json(serde_json::json!({ "error": error.to_string() })),
        )
            .into_response(),
    }
}

async fn post_config_update<S>(
    State(state): State<AppState<S>>,
    Json(payload): Json<ConfigUpdate>,
) -> impl IntoResponse
where
    S: IndexerService,
{
    match state.service.apply_config(payload).await {
        Ok(()) => StatusCode::ACCEPTED.into_response(),
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": error.to_string() })),
        )
            .into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{
        AgentNetworkReport, ConfigUpdate, IndexerStats, Protocol, SearchJob, SearchKind,
    };
    use anyhow::Result;
    use async_trait::async_trait;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpStream,
    };
    use uuid::Uuid;

    struct FakeService {
        indexer_id: Uuid,
    }

    #[async_trait]
    impl IndexerService for FakeService {
        fn protocol(&self) -> Protocol {
            Protocol::Kad2
        }

        fn version(&self) -> &str {
            "test"
        }

        fn indexer_id(&self) -> Uuid {
            self.indexer_id
        }

        async fn start(&self) -> Result<()> {
            Ok(())
        }

        async fn stop(&self) -> Result<()> {
            Ok(())
        }

        async fn search(&self, _job: SearchJob) -> Result<()> {
            Ok(())
        }

        async fn cancel_search(&self, _job_id: Uuid) -> Result<()> {
            Ok(())
        }

        async fn stats(&self) -> Result<IndexerStats> {
            Ok(IndexerStats {
                indexer_id: self.indexer_id,
                protocol: Protocol::Kad2,
                peers_connected: 0,
                crawl_rate: 0.0,
                snoop_queue_depth: 0,
                staging_queue_depth: 0,
                uptime_secs: 0,
                nat: None,
                interface_report: None,
                publish_observability: None,
                harvest_observability: None,
            })
        }

        async fn apply_config(&self, _config: ConfigUpdate) -> Result<()> {
            Ok(())
        }

        async fn interfaces(&self) -> Result<AgentNetworkReport> {
            Err(anyhow::anyhow!("unused in test"))
        }
    }

    #[tokio::test]
    async fn shutdown_does_not_wait_forever_for_idle_keep_alive_connections() {
        let server = IndexerServer::new(Arc::new(FakeService {
            indexer_id: Uuid::new_v4(),
        }))
        .spawn("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();

        let mut socket = TcpStream::connect(server.local_addr()).await.unwrap();
        socket
            .write_all(
                format!(
                    "GET /api/internal/health HTTP/1.1\r\nHost: {}\r\nConnection: keep-alive\r\n\r\n",
                    server.local_addr()
                )
                .as_bytes(),
            )
            .await
            .unwrap();

        let mut response = vec![0_u8; 2048];
        let read = socket.read(&mut response).await.unwrap();
        assert!(read > 0);
        assert!(String::from_utf8_lossy(&response[..read]).contains("\"ok\":true"));

        timeout(Duration::from_secs(5), server.shutdown())
            .await
            .expect("shutdown should complete even if the client keeps the socket open")
            .unwrap();

        let _ = socket
            .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await;
    }

    #[tokio::test]
    async fn accepts_typed_search_payloads() {
        let server = IndexerServer::new(Arc::new(FakeService {
            indexer_id: Uuid::new_v4(),
        }))
        .spawn("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();

        let client = reqwest::Client::new();
        let response = client
            .post(format!(
                "http://{}/api/internal/search",
                server.local_addr()
            ))
            .json(&serde_json::json!({
                "job_id": Uuid::new_v4(),
                "protocol": Protocol::Kad2,
                "kind": SearchKind::Keyword,
                "query": "test file",
                "file_hash": null,
                "file_size": null,
                "callback_url": "http://127.0.0.1:13300"
            }))
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::ACCEPTED);

        server.shutdown().await.unwrap();
    }
}
