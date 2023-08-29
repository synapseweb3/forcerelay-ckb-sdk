use std::time::Duration;

use anyhow::{anyhow, bail, ensure, Context as _, Result};
use ckb_ics_axon::{
    handler::{IbcChannel, IbcPacket},
    message::{Envelope, MsgType},
    PacketArgs,
};
use ckb_jsonrpc_types::{CellOutput, OutPoint, Script, TransactionView};
use ckb_sdk::rpc::ckb_indexer;
use ckb_types::{
    packed,
    prelude::{Builder, Entity, Reader},
};
use futures::Stream;
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, TryFromIntoRef};

use crate::{ckb_rpc_client::CkbRpcClient, config::Config, json::*, utils::keccak256};

#[serde_as]
#[derive(Serialize, Deserialize)]
pub struct PacketCell {
    pub tx: TransactionView,
    pub packet_cell_idx: usize,
    pub channel: IbcChannelCell,
    #[serde_as(as = "TryFromIntoRef<JsonIbcPacket>")]
    pub packet: IbcPacket,
    #[serde_as(as = "TryFromIntoRef<JsonEnvelope>")]
    pub envelope: Envelope,
}

impl PacketCell {
    /// Search for and parse live packet cells.
    pub async fn search(
        client: &CkbRpcClient,
        config: &Config,
        limit: u32,
        first_block_to_search: &mut u64,
    ) -> Result<Vec<Self>> {
        search_packet_cells(client, config, limit, first_block_to_search).await
    }

    pub fn subscribe(client: CkbRpcClient, config: Config) -> impl Stream<Item = Result<Self>> {
        async_stream::try_stream! {
            let mut cursor = 0;
            loop {
                let cells = search_packet_cells(&client, &config, 64, &mut cursor).await?;
                for c in cells {
                    yield c;
                }
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        }
    }

    /// Parse packet, channel and envelope. This is a pure function.
    pub fn parse(tx: TransactionView, packet_cell_idx: usize, config: &Config) -> Result<Self> {
        parse_packet_tx(tx, packet_cell_idx, config)
    }

    pub fn as_input(&self) -> packed::CellInput {
        packed::CellInput::new_builder()
            .previous_output(
                OutPoint {
                    tx_hash: self.tx.hash.clone(),
                    index: (self.packet_cell_idx as u32).into(),
                }
                .into(),
            )
            .build()
    }

    /// Is RecvPacket. You should send an WriteAck packet with
    /// [assemble_write_ack_partial_transaction](`crate::transaction::assemble_write_ack_partial_transaction`).
    pub fn is_recv_packet(&self) -> bool {
        matches!(self.envelope.msg_type, MsgType::MsgRecvPacket)
    }

    /// Is AckPacket. You should consume it with
    /// [assemble_consume_ack_packet_partial_transaction](`crate::transaction::assemble_consume_ack_packet_partial_transaction`).
    pub fn is_ack_packet(&self) -> bool {
        // XXX: is this correct?
        matches!(self.envelope.msg_type, MsgType::MsgAckPacket)
    }
}

async fn search_packet_cells(
    client: &CkbRpcClient,
    config: &Config,
    limit: u32,
    first_block_to_search: &mut u64,
) -> Result<Vec<PacketCell>> {
    ensure!(limit > 0);
    let tip = client
        .get_indexer_tip()
        .await?
        .map_or(0, |t| t.block_number.into());
    let last_block_to_search = tip.saturating_sub(config.confirmations.into());
    if *first_block_to_search > last_block_to_search {
        return Ok(vec![]);
    }
    let cells = client
        .get_cells(
            ckb_indexer::SearchKey {
                filter: Some(ckb_indexer::SearchKeyFilter {
                    block_range: Some([
                        (*first_block_to_search).into(),
                        // +1 because this is exclusive.
                        last_block_to_search.saturating_add(1).into(),
                    ]),
                    ..Default::default()
                }),
                group_by_transaction: Some(true),
                script: config.packet_cell_lock_script_prefix().into(),
                script_type: ckb_indexer::ScriptType::Lock,
                script_search_mode: Some(ckb_indexer::ScriptSearchMode::Prefix),
                with_data: Some(false),
            },
            ckb_indexer::Order::Asc,
            limit.into(),
            None,
        )
        .await?;

    // No result. Don't update cursor.
    if cells.last_cursor.is_empty() {
        return Ok(Vec::new());
    }

    let mut result = Vec::new();
    for c in cells.objects {
        let tx = client
            .get_transaction(c.out_point.tx_hash.clone())
            .await?
            .transaction
            .context("get transaction")?;
        let p = match parse_packet_tx(tx, c.out_point.index.value() as usize, config) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!("failed to parse packet tx {}: {e:#}", c.out_point.tx_hash);
                continue;
            }
        };
        result.push(p);
    }
    *first_block_to_search = last_block_to_search.saturating_add(1);
    Ok(result)
}

fn parse_packet_tx(
    tx: TransactionView,
    packet_cell_idx: usize,
    config: &Config,
) -> Result<PacketCell> {
    let lock_args = tx
        .inner
        .outputs
        .get(packet_cell_idx)
        .context("get output")?
        .lock
        .args
        .as_bytes();
    PacketArgs::from_slice(lock_args).map_err(|_e| anyhow!("parse packet args"))?;

    let channel_lock = config.channel_cell_lock_script().into();
    let channel_cell_idx = tx
        .inner
        .outputs
        .iter()
        .position(|o| o.lock == channel_lock)
        .context("channel cell not found")?;

    let channel = IbcChannelCell::parse(&tx, channel_cell_idx)?;

    let packet_bytes = get_witness_output_type_and_verify_hash(&tx, packet_cell_idx)
        .context("get packet witness")?;
    let packet: IbcPacket = rlp::decode(packet_bytes).context("parse packet")?;

    // XXX: assuming envelope is the last.
    let envelope_witness = tx.inner.witnesses.last().context("get envelope witness")?;
    let envelope_witness = packed::WitnessArgsReader::from_slice(envelope_witness.as_bytes())
        .context("parse envelope witness")?;
    let envelope_bytes = envelope_witness
        .output_type()
        .to_opt()
        .context("get envelope witness output type")?
        .raw_data();
    let envelope: Envelope = rlp::decode(envelope_bytes).context("parse envelope")?;

    Ok(PacketCell {
        tx,
        packet_cell_idx,
        channel,
        packet,
        envelope,
    })
}

fn get_witness_output_type_and_verify_hash(tx: &TransactionView, idx: usize) -> Result<&[u8]> {
    let witness = tx.inner.witnesses.get(idx).context("get witness")?;
    let witness =
        packed::WitnessArgsReader::from_slice(witness.as_bytes()).context("parse witness")?;
    let output_type = witness
        .output_type()
        .to_opt()
        .context("no output type")?
        .raw_data();

    let witness_hash = keccak256(output_type);
    let data = tx.inner.outputs_data.get(idx).context("get output data")?;
    if data.as_bytes() != witness_hash {
        bail!("witness output type hash doesn't match");
    }
    Ok(output_type)
}

pub async fn get_latest_cell_by_type_script(
    client: &CkbRpcClient,
    type_script: Script,
) -> Result<ckb_indexer::Cell> {
    let mut cells = client
        .get_cells(
            ckb_indexer::SearchKey {
                filter: None,
                group_by_transaction: Some(true),
                script: type_script,
                script_search_mode: Some(ckb_indexer::ScriptSearchMode::Exact),
                script_type: ckb_indexer::ScriptType::Type,
                with_data: Some(false),
            },
            ckb_indexer::Order::Desc,
            1.into(),
            None,
        )
        .await?;
    if cells.objects.is_empty() {
        bail!("cell not found");
    }
    Ok(cells.objects.remove(0))
}

pub async fn get_latest_cell_by_lock_script(
    client: &CkbRpcClient,
    lock_script: Script,
) -> Result<ckb_indexer::Cell> {
    let mut cells = client
        .get_cells(
            ckb_indexer::SearchKey {
                filter: None,
                group_by_transaction: Some(true),
                script: lock_script,
                script_search_mode: Some(ckb_indexer::ScriptSearchMode::Exact),
                script_type: ckb_indexer::ScriptType::Lock,
                with_data: Some(false),
            },
            ckb_indexer::Order::Desc,
            1.into(),
            None,
        )
        .await?;
    if cells.objects.is_empty() {
        bail!("cell not found");
    }
    Ok(cells.objects.remove(0))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IbcChannelCell {
    pub out_point: OutPoint,
    pub output: CellOutput,
    #[serde(with = "JsonIbcChannel")]
    pub channel: IbcChannel,
}

impl IbcChannelCell {
    pub async fn get_latest(client: &CkbRpcClient, config: &Config) -> Result<Self> {
        let channel_cell =
            get_latest_cell_by_lock_script(client, config.channel_cell_lock_script().into())
                .await
                .context("get channel cell")?;
        let tx = client
            .get_transaction(channel_cell.out_point.tx_hash.clone())
            .await?
            .transaction
            .context("get transaction")?;
        let idx = channel_cell.out_point.index.value() as usize;
        Self::parse(&tx, idx)
    }

    /// Pure function.
    pub fn parse(tx: &TransactionView, index: usize) -> Result<Self> {
        let channel_bytes =
            get_witness_output_type_and_verify_hash(tx, index).context("get channel bytes")?;
        let channel = rlp::decode(channel_bytes).context("decode channel")?;
        let out_point = OutPoint {
            tx_hash: tx.hash.clone(),
            index: (index as u32).into(),
        };
        let output = tx.inner.outputs.get(index).context("get output")?.clone();
        Ok(IbcChannelCell {
            out_point,
            output,
            channel,
        })
    }

    pub fn as_input(&self) -> packed::CellInput {
        packed::CellInput::new_builder()
            .previous_output(self.out_point.clone().into())
            .build()
    }
}

pub async fn get_axon_metadata_cell_dep(
    client: &CkbRpcClient,
    config: &Config,
) -> Result<packed::CellDep> {
    let cell = get_latest_cell_by_type_script(client, config.axon_metadata_type_script().into())
        .await
        .context("get axon metadata cell")?;

    Ok(packed::CellDep::new_builder()
        .out_point(cell.out_point.into())
        .build())
}

pub async fn get_channel_contract_cell_dep(
    client: &CkbRpcClient,
    config: &Config,
) -> Result<packed::CellDep> {
    let cell = get_latest_cell_by_type_script(client, config.channel_contract_type_script().into())
        .await
        .context("get channel contract cell")?;

    Ok(packed::CellDep::new_builder()
        .out_point(cell.out_point.into())
        .build())
}

pub async fn get_packet_contract_cell_dep(
    client: &CkbRpcClient,
    config: &Config,
) -> Result<packed::CellDep> {
    let cell = get_latest_cell_by_type_script(client, config.packet_contract_type_script().into())
        .await
        .context("get packet contract cell")?;

    Ok(packed::CellDep::new_builder()
        .out_point(cell.out_point.into())
        .build())
}
