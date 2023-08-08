use anyhow::{bail, Context as _, Result};
use ckb_ics_axon::handler::IbcChannel;
use ckb_jsonrpc_types::Either;
use ckb_sdk::{
    traits::{CellCollector, CellQueryOptions, LiveCell, QueryOrder},
    CkbRpcClient,
};
use ckb_types::{packed, prelude::*};

use crate::config::Config;

pub fn get_unique_cell_by_type_script(
    collector: &mut dyn CellCollector,
    type_script: packed::Script,
) -> Result<LiveCell> {
    let mut options = CellQueryOptions::new_type(type_script);
    options.with_data = Some(true);
    let (mut cells, _) = collector.collect_live_cells(&options, false)?;

    if cells.is_empty() {
        bail!("cell not found");
    } else if cells.len() > 1 {
        bail!("more than one ({}) cell found", cells.len());
    }

    Ok(cells.remove(0))
}

pub fn get_last_cell_by_lock_script(
    collector: &mut dyn CellCollector,
    lock_script: packed::Script,
) -> Result<LiveCell> {
    let mut options = CellQueryOptions::new_lock(lock_script);
    options.order = QueryOrder::Desc;

    let (mut cells, _) = collector.collect_live_cells(&options, false)?;

    if cells.is_empty() {
        bail!("cell not found");
    }

    Ok(cells.remove(0))
}

/// Get channel cell, channel data, and the transaction.
pub fn get_channel_cell(
    client: &CkbRpcClient,
    collector: &mut dyn CellCollector,
    config: &Config,
) -> Result<(LiveCell, IbcChannel, packed::Transaction)> {
    // TODO: confirmations.
    let cell = get_last_cell_by_lock_script(collector, config.channel_cell_lock_script())
        .context("get channel cell by lock script")?;

    let tx = client
        .get_packed_transaction(cell.out_point.tx_hash().unpack())
        .context("get channel cell transaction")?
        .transaction
        .context("get channel cell transaction")?;

    let tx = match tx.inner {
        Either::Left(_tx) => bail!("unexpected json response for get packed transaction"),
        Either::Right(tx) => packed::Transaction::from_slice(tx.as_bytes())?,
    };

    let cell_data = &cell.output_data;

    let witness = tx
        .witnesses()
        .get(cell.out_point.index().unpack())
        .context("failed to get channel cell witness")?;

    if cell_data != witness.calc_raw_data_hash().as_slice() {
        bail!("cell data doesn't match witness");
    }

    let channel = rlp::decode(&witness.raw_data()[..]).context("decode channel data")?;

    Ok((cell, channel, tx))
}
