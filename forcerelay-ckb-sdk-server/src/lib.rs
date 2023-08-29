use async_trait::async_trait;
use ckb_jsonrpc_types::{CellDep, Transaction, TransactionView};
use ckb_types::packed;
use forcerelay_ckb_sdk::{
    ckb_jsonrpc_types,
    ckb_rpc_client::CkbRpcClient,
    ckb_types,
    config::Config,
    json::{HexBytes, JsonEnvelope},
    search::{
        get_axon_metadata_cell_dep, get_channel_contract_cell_dep, get_packet_contract_cell_dep,
        IbcChannelCell, PacketCell,
    },
    transaction::{
        add_ibc_envelope, assemble_consume_ack_packet_partial_transaction,
        assemble_send_packet_partial_transaction, assemble_write_ack_partial_transaction,
    },
};
use futures::StreamExt;
use jsonrpc_utils::{
    jsonrpc_core::{
        futures_util::{stream::BoxStream, Stream},
        Result,
    },
    pub_sub::PublishMsg,
    rpc,
};
use serde::Deserialize;
use serde_with::{serde_as, DefaultOnNull, DisplayFromStr};

#[rpc]
#[async_trait]
pub trait Rpc {
    async fn search_packet_cells(&self, config: Config, limit: u32) -> Result<Vec<PacketCell>>;
    async fn get_latest_channel_cell(&self, config: Config) -> Result<IbcChannelCell>;

    async fn get_axon_metadata_cell_dep(&self, config: Config) -> Result<CellDep>;
    async fn get_channel_contract_cell_dep(&self, config: Config) -> Result<CellDep>;
    async fn get_packet_contract_cell_dep(&self, config: Config) -> Result<CellDep>;

    type PS: Stream<Item = PublishMsg<PacketCell>> + Send + 'static;
    #[rpc(pub_sub(notify = "packet_cells", unsubscribe = "unsubscribe_packet_cells"))]
    fn subscribe_packet_cells(&self, config: Config) -> Result<Self::PS>;

    fn parse_channel_cell(&self, tx: TransactionView, index: usize) -> Result<IbcChannelCell>;
    fn parse_packet_cell(
        &self,
        tx: TransactionView,
        packet_cell_idx: usize,
        config: Config,
    ) -> Result<PacketCell>;

    fn add_ibc_envelope(&self, tx: Transaction, envelope: JsonEnvelope) -> Result<Transaction>;

    fn assemble_send_packet_partial_transaction(
        &self,
        params: SendPacketParams,
    ) -> Result<(Transaction, JsonEnvelope)>;
    fn assemble_write_ack_partial_transaction(
        &self,
        params: WriteAckParams,
    ) -> Result<(Transaction, JsonEnvelope)>;
    fn assemble_consume_ack_packet_partial_transaction(
        &self,
        params: ConsumeAckParams,
    ) -> Result<Transaction>;
}

#[serde_as]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SendPacketParams {
    pub axon_metadata_cell_dep: CellDep,
    pub channel_contract_cell_dep: CellDep,
    pub config: Config,
    pub channel: IbcChannelCell,
    #[serde_as(as = "HexBytes")]
    pub data: Vec<u8>,
    #[serde_as(as = "DefaultOnNull<DisplayFromStr>")]
    pub timeout_height: u64,
    #[serde_as(as = "DefaultOnNull<DisplayFromStr>")]
    pub timeout_timestamp: u64,
}

#[serde_as]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WriteAckParams {
    pub axon_metadata_cell_dep: CellDep,
    pub channel_contract_cell_dep: CellDep,
    pub packet_contract_cell_dep: CellDep,
    pub config: Config,
    pub channel: IbcChannelCell,
    pub packet: PacketCell,
    #[serde_as(as = "HexBytes")]
    pub ack_message: Vec<u8>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsumeAckParams {
    pub packet_contract_cell_dep: CellDep,
    pub ack_packet_cell: PacketCell,
}

#[derive(Clone)]
pub struct RpcImpl {
    client: CkbRpcClient,
}

impl RpcImpl {
    pub fn new(url: String) -> Self {
        Self {
            client: CkbRpcClient::new(url),
        }
    }
}

#[async_trait]
impl Rpc for RpcImpl {
    async fn search_packet_cells(&self, config: Config, limit: u32) -> Result<Vec<PacketCell>> {
        PacketCell::search(&self.client, &config, limit)
            .await
            .map_err(internal_error)
    }
    async fn get_latest_channel_cell(&self, config: Config) -> Result<IbcChannelCell> {
        IbcChannelCell::get_latest(&self.client, &config)
            .await
            .map_err(internal_error)
    }
    async fn get_axon_metadata_cell_dep(&self, config: Config) -> Result<CellDep> {
        get_axon_metadata_cell_dep(&self.client, &config)
            .await
            .map(Into::into)
            .map_err(internal_error)
    }
    async fn get_channel_contract_cell_dep(&self, config: Config) -> Result<CellDep> {
        get_channel_contract_cell_dep(&self.client, &config)
            .await
            .map(Into::into)
            .map_err(internal_error)
    }
    async fn get_packet_contract_cell_dep(&self, config: Config) -> Result<CellDep> {
        get_packet_contract_cell_dep(&self.client, &config)
            .await
            .map(Into::into)
            .map_err(internal_error)
    }

    type PS = BoxStream<'static, PublishMsg<PacketCell>>;
    fn subscribe_packet_cells(&self, config: Config) -> Result<Self::PS> {
        Ok(PacketCell::subscribe(self.client.clone(), config)
            .map(|r| match r {
                Ok(r) => PublishMsg::result(&r),
                Err(e) => PublishMsg::error(&internal_error(e)),
            })
            .boxed())
    }

    fn parse_channel_cell(&self, tx: TransactionView, index: usize) -> Result<IbcChannelCell> {
        IbcChannelCell::parse(&tx, index).map_err(internal_error)
    }
    fn parse_packet_cell(
        &self,
        tx: TransactionView,
        packet_cell_idx: usize,
        config: Config,
    ) -> Result<PacketCell> {
        PacketCell::parse(tx, packet_cell_idx, &config).map_err(internal_error)
    }

    fn add_ibc_envelope(&self, tx: Transaction, envelope: JsonEnvelope) -> Result<Transaction> {
        let mut tx = packed::Transaction::from(tx).as_advanced_builder();
        tx = add_ibc_envelope(tx, &envelope.into());
        Ok(tx.build().data().into())
    }

    fn assemble_send_packet_partial_transaction(
        &self,
        params: SendPacketParams,
    ) -> Result<(Transaction, JsonEnvelope)> {
        assemble_send_packet_partial_transaction(
            params.axon_metadata_cell_dep.into(),
            params.channel_contract_cell_dep.into(),
            &params.config,
            params.channel,
            params.data,
            params.timeout_height,
            params.timeout_timestamp,
        )
        .map(|(t, e)| (t.build().data().into(), (&e).into()))
        .map_err(internal_error)
    }
    fn assemble_write_ack_partial_transaction(
        &self,
        params: WriteAckParams,
    ) -> Result<(Transaction, JsonEnvelope)> {
        assemble_write_ack_partial_transaction(
            params.axon_metadata_cell_dep.into(),
            params.channel_contract_cell_dep.into(),
            params.packet_contract_cell_dep.into(),
            &params.config,
            params.channel,
            params.packet,
            params.ack_message,
        )
        .map(|(t, e)| (t.build().data().into(), (&e).into()))
        .map_err(internal_error)
    }
    fn assemble_consume_ack_packet_partial_transaction(
        &self,
        params: ConsumeAckParams,
    ) -> Result<Transaction> {
        assemble_consume_ack_packet_partial_transaction(
            params.packet_contract_cell_dep.into(),
            params.ack_packet_cell,
        )
        .map(|t| t.build().data().into())
        .map_err(internal_error)
    }
}

fn internal_error(e: anyhow::Error) -> jsonrpc_utils::jsonrpc_core::Error {
    jsonrpc_utils::jsonrpc_core::Error {
        code: jsonrpc_utils::jsonrpc_core::ErrorCode::InternalError,
        message: format!("{e:#}"),
        data: None,
    }
}
