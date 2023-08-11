use anyhow::{bail, Context as _, Result};
use ckb_fixed_hash::H256;
use ckb_hash::blake2b_256;
use ckb_ics_axon::{
    handler::IbcChannel,
    message::{Envelope, MsgType},
    object::Packet,
    PacketArgs,
};
use ckb_jsonrpc_types::{Either, OutPoint, Script, TransactionView};
use ckb_sdk::{rpc::ckb_indexer, CkbRpcClient, IndexerRpcClient};
use ckb_types::{
    packed,
    prelude::{Builder, Entity, Reader},
};

use crate::config::Config;

pub struct PacketCell {
    pub tx: TransactionView,
    pub packet_cell_idx: usize,
    pub channel: IbcChannelCell,
    pub packet: Packet,
    pub envelope: Envelope,
}

impl PacketCell {
    /// Search for and parse live packet cells.
    pub fn search(
        client: &CkbRpcClient,
        indexer: &IndexerRpcClient,
        config: &Config,
        from_block: u64,
        from_sequence: u16,
        limit: u32,
    ) -> Result<Vec<Self>> {
        search_packet_cells(client, indexer, config, from_block, from_sequence, limit)
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

macro_rules! or_continue {
    ($e:expr) => {
        match $e {
            Ok(a) => a,
            Err(_) => continue,
        }
    };
}

fn search_packet_cells(
    client: &CkbRpcClient,
    indexer: &IndexerRpcClient,
    config: &Config,
    from_block: u64,
    from_sequence: u16,
    limit: u32,
) -> Result<Vec<PacketCell>> {
    let tip = indexer
        .get_indexer_tip()?
        .map_or(0, |t| t.block_number.into());
    let cells = indexer.get_cells(
        ckb_indexer::SearchKey {
            filter: Some(ckb_indexer::SearchKeyFilter {
                block_range: Some([
                    from_block.into(),
                    tip.saturating_add(1)
                        .saturating_sub(config.confirmations.into())
                        .into(),
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
    )?;

    let mut result = Vec::new();
    for c in cells.objects {
        let args = &c.output.lock.args;
        let packet = or_continue!(PacketArgs::from_slice(args.as_bytes()));
        if packet.sequence >= from_sequence {
            let tx = get_transaction(client, c.out_point.tx_hash)?;
            let p = or_continue!(parse_packet_tx(
                tx,
                c.out_point.index.value() as usize,
                config
            ));
            result.push(p);
        }
    }
    Ok(result)
}

fn parse_packet_tx(
    tx: TransactionView,
    packet_cell_idx: usize,
    config: &Config,
) -> Result<PacketCell> {
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
    let packet: Packet = rlp::decode(packet_bytes).context("parse packet")?;

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

    let witness_hash = blake2b_256(output_type);
    let data = tx.inner.outputs_data.get(idx).context("get output data")?;
    if data.as_bytes() != witness_hash {
        bail!("witness output type hash doesn't match");
    }
    Ok(output_type)
}

pub fn get_transaction(client: &CkbRpcClient, tx_hash: H256) -> Result<TransactionView> {
    let tx = client
        .get_transaction(tx_hash)?
        .context("transaction not found")?
        .transaction
        .context("transaction not found")?;
    match tx.inner {
        Either::Left(tx) => Ok(tx),
        Either::Right(_) => bail!("unexpected bytes response for get_transaction"),
    }
}

pub fn get_latest_cell_by_type_script(
    indexer: &IndexerRpcClient,
    type_script: Script,
) -> Result<ckb_indexer::Cell> {
    let mut cells = indexer.get_cells(
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
    )?;
    if cells.objects.is_empty() {
        bail!("cell not found");
    }
    Ok(cells.objects.remove(0))
}

pub fn get_latest_cell_by_lock_script(
    indexer: &IndexerRpcClient,
    lock_script: Script,
) -> Result<ckb_indexer::Cell> {
    let mut cells = indexer.get_cells(
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
    )?;
    if cells.objects.is_empty() {
        bail!("cell not found");
    }
    Ok(cells.objects.remove(0))
}

#[derive(Debug, Clone)]
pub struct IbcChannelCell {
    pub out_point: packed::OutPoint,
    pub output: packed::CellOutput,
    pub channel: IbcChannel,
}

impl IbcChannelCell {
    pub fn get_latest(
        client: &CkbRpcClient,
        indexer: &IndexerRpcClient,
        config: &Config,
    ) -> Result<Self> {
        let channel_cell =
            get_latest_cell_by_lock_script(indexer, config.channel_cell_lock_script().into())
                .context("get channel cell")?;
        let tx = get_transaction(client, channel_cell.out_point.tx_hash.clone())
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
        }
        .into();
        let output = tx
            .inner
            .outputs
            .get(index)
            .context("get output")?
            .clone()
            .into();
        Ok(IbcChannelCell {
            out_point,
            output,
            channel,
        })
    }

    pub fn as_input(&self) -> packed::CellInput {
        packed::CellInput::new_builder()
            .previous_output(self.out_point.clone())
            .build()
    }
}

pub fn get_axon_metadata_cell_dep(
    indexer: &IndexerRpcClient,
    config: &Config,
) -> Result<packed::CellDep> {
    let cell = get_latest_cell_by_type_script(indexer, config.axon_metadata_type_script().into())
        .context("get axon metadata cell")?;

    Ok(packed::CellDep::new_builder()
        .out_point(cell.out_point.into())
        .build())
}

pub fn get_channel_contract_cell_dep(
    indexer: &IndexerRpcClient,
    config: &Config,
) -> Result<packed::CellDep> {
    let cell =
        get_latest_cell_by_type_script(indexer, config.channel_contract_type_script().into())
            .context("get channel contract cell")?;

    Ok(packed::CellDep::new_builder()
        .out_point(cell.out_point.into())
        .build())
}

pub fn get_packet_contract_cell_dep(
    indexer: &IndexerRpcClient,
    config: &Config,
) -> Result<packed::CellDep> {
    let cell = get_latest_cell_by_type_script(indexer, config.packet_contract_type_script().into())
        .context("get packet contract cell")?;

    Ok(packed::CellDep::new_builder()
        .out_point(cell.out_point.into())
        .build())
}
