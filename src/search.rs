use anyhow::{bail, Context as _, Result};
use ckb_fixed_hash::H256;
use ckb_hash::blake2b_256;
use ckb_ics_axon::{handler::IbcChannel, message::Envelope, object::Packet, PacketArgs};
use ckb_jsonrpc_types::{Either, TransactionView};
use ckb_sdk::{rpc::ckb_indexer, CkbRpcClient, IndexerRpcClient};
use ckb_types::{packed::WitnessArgsReader, prelude::Reader};

use crate::config::Config;

pub struct PacketTx {
    pub tx: TransactionView,
    pub channel: IbcChannel,
    pub packet: Packet,
    pub envelope: Envelope,
}

macro_rules! or_continue {
    ($e:expr) => {
        match $e {
            Ok(a) => a,
            Err(_) => continue,
        }
    };
}

/// Search for and parse live packet cells.
pub fn get_packet_cells(
    client: &CkbRpcClient,
    indexer: &IndexerRpcClient,
    config: &Config,
    from_block: u64,
    from_sequence: u16,
    limit: u32,
) -> Result<Vec<PacketTx>> {
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
            let (channel, packet, envelope) = or_continue!(parse_packet_tx(
                &tx,
                c.out_point.index.value() as usize,
                config
            ));
            result.push(PacketTx {
                tx,
                channel,
                packet,
                envelope,
            });
        }
    }
    Ok(result)
}

/// Parse packet, channel and envelope. This is a pure function.
pub fn parse_packet_tx(
    tx: &TransactionView,
    packet_cell_idx: usize,
    config: &Config,
) -> Result<(IbcChannel, Packet, Envelope)> {
    let channel_lock = config.channel_cell_lock_script().into();
    let channel_cell_idx = tx
        .inner
        .outputs
        .iter()
        .position(|o| o.lock == channel_lock)
        .context("channel cell not found")?;

    let channel_bytes = get_witness_output_type_and_verify_hash(tx, channel_cell_idx)
        .context("get channel witness")?;
    let channel: IbcChannel = rlp::decode(channel_bytes).context("parse channel")?;

    let packet_bytes = get_witness_output_type_and_verify_hash(tx, packet_cell_idx)
        .context("get packet witness")?;
    let packet: Packet = rlp::decode(packet_bytes).context("parse packet")?;

    // XXX: assuming envelope is the last.
    let envelope_witness = tx.inner.witnesses.last().context("get envelope witness")?;
    let envelope: Envelope = rlp::decode(envelope_witness.as_bytes()).context("parse envelope")?;

    Ok((channel, packet, envelope))
}

fn get_witness_output_type_and_verify_hash(tx: &TransactionView, idx: usize) -> Result<&[u8]> {
    let witness = tx.inner.witnesses.get(idx).context("get witness")?;
    let witness = WitnessArgsReader::from_slice(witness.as_bytes()).context("parse witness")?;
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
