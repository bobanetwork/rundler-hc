use std::str::FromStr;

use ethers::types::{Address, H256};
use rundler_task::{
    grpc::protos::{from_bytes, ConversionError},
    server::{HealthCheck, ServerStatus},
};
use tonic::{
    async_trait,
    transport::{Channel, Uri},
};
use tonic_health::{
    pb::{health_client::HealthClient, HealthCheckRequest},
    ServingStatus,
};

use super::protos::{
    builder_client::BuilderClient, debug_send_bundle_now_response,
    debug_set_bundling_mode_response, BundlingMode as ProtoBundlingMode, DebugSendBundleNowRequest,
    DebugSetBundlingModeRequest, GetSupportedEntryPointsRequest,
};
use crate::builder::{
    server::{BuilderResult, BuilderServer, BuilderServerError},
    BundlingMode,
};

#[derive(Debug, Clone)]
pub struct RemoteBuilderClient {
    grpc_client: BuilderClient<Channel>,
    health_client: HealthClient<Channel>,
}

impl RemoteBuilderClient {
    pub async fn connect(url: String) -> anyhow::Result<Self> {
        let grpc_client = BuilderClient::connect(url.clone()).await?;
        let health_client =
            HealthClient::new(Channel::builder(Uri::from_str(&url)?).connect().await?);
        Ok(Self {
            grpc_client,
            health_client,
        })
    }
}

#[async_trait]
impl BuilderServer for RemoteBuilderClient {
    async fn get_supported_entry_points(&self) -> BuilderResult<Vec<Address>> {
        Ok(self
            .grpc_client
            .clone()
            .get_supported_entry_points(GetSupportedEntryPointsRequest {})
            .await?
            .into_inner()
            .entry_points
            .into_iter()
            .map(|ep| from_bytes(ep.as_slice()))
            .collect::<Result<_, ConversionError>>()?)
    }

    async fn debug_send_bundle_now(&self) -> BuilderResult<H256> {
        let res = self
            .grpc_client
            .clone()
            .debug_send_bundle_now(DebugSendBundleNowRequest {})
            .await?
            .into_inner()
            .result;

        match res {
            Some(debug_send_bundle_now_response::Result::Success(s)) => {
                Ok(H256::from_slice(&s.transaction_hash))
            }
            Some(debug_send_bundle_now_response::Result::Failure(f)) => Err(f.try_into()?),
            None => Err(BuilderServerError::Other(anyhow::anyhow!(
                "should have received result from builder"
            )))?,
        }
    }

    async fn debug_set_bundling_mode(&self, mode: BundlingMode) -> BuilderResult<()> {
        let res = self
            .grpc_client
            .clone()
            .debug_set_bundling_mode(DebugSetBundlingModeRequest {
                mode: ProtoBundlingMode::from(mode) as i32,
            })
            .await?
            .into_inner()
            .result;

        match res {
            Some(debug_set_bundling_mode_response::Result::Success(_)) => Ok(()),
            Some(debug_set_bundling_mode_response::Result::Failure(f)) => Err(f.try_into()?),
            None => Err(BuilderServerError::Other(anyhow::anyhow!(
                "should have received result from builder"
            )))?,
        }
    }
}

#[async_trait]
impl HealthCheck for RemoteBuilderClient {
    fn name(&self) -> &'static str {
        "RemoteBuilderServer"
    }

    async fn status(&self) -> ServerStatus {
        self.health_client
            .clone()
            .check(HealthCheckRequest::default())
            .await
            .ok()
            .filter(|status| status.get_ref().status == ServingStatus::Serving as i32)
            .map(|_| ServerStatus::Serving)
            .unwrap_or(ServerStatus::NotServing)
    }
}
