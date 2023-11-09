//! An example cli for sending/receiving SUDT with the sudt transfer module.

use std::{collections::HashMap, fmt, fs, path::PathBuf, pin::pin, time::Duration};

use anyhow::{bail, ensure, Context, Result};
use bytes::Bytes;
use ckb_jsonrpc_types as json;
use ckb_sdk::{
    constants::SIGHASH_TYPE_HASH,
    rpc::{ckb_indexer, ckb_light_client::Cell},
    traits::{
        DefaultCellCollector, DefaultCellDepResolver, DefaultHeaderDepResolver,
        DefaultTransactionDependencyProvider, SecpCkbRawKeySigner,
    },
    tx_builder::{unlock_tx, CapacityBalancer},
    unlock::{ScriptUnlocker, SecpSighashUnlocker},
    AddressPayload, ScriptId,
};
use ckb_types::{
    core::{Capacity, TransactionView},
    packed,
    prelude::{Builder, Entity, Pack, Unpack},
};
use clap::{Parser, Subcommand};
use forcerelay_ckb_sdk::{
    ckb_rpc_client::CkbRpcClient,
    config::Config as SdkConfig,
    search::{get_latest_cell_by_type_script, IbcChannelCell, PacketCell},
    transaction::{
        add_ibc_envelope, assemble_consume_ack_packet_partial_transaction,
        assemble_send_packet_partial_transaction, assemble_write_ack_partial_transaction,
    },
};
use futures::TryStreamExt;
use prost::Message;
use secp256k1::Secp256k1;
use serde::Deserialize;
use tokio::task::block_in_place;

#[derive(Parser)]
struct Cli {
    #[arg(short, long, value_name = "FILE")]
    config: PathBuf,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Send SUDT
    Send {
        #[arg(short, long, value_name = "SUDT NAME", alias = "sudt-type-script")]
        sudt: String,
        #[arg(short, long, value_name = "HEX ADDRESS")]
        receiver: String,
        #[arg(short, long)]
        amount: u128,
    },
    /// Create st-cell
    CreateStCell {
        #[arg(short, long, value_name = "SUDT NAME", alias = "sudt-type-script")]
        sudt: String,
    },
    /// Consume ACK
    ConsumeAck,
    /// Receive SUDT
    Recv,
}

#[derive(Deserialize)]
struct Config {
    #[serde(flatten)]
    sdk_config: SdkConfig,
    /// Specify end user sighash(secp256k1) private key in hex without 0x
    /// prefix, or read the key from a binary file, or pass the key (still in
    /// hex without 0x prefix) via the SUDT_TRANSFER_PRIVATE_KEY environment
    /// variable.
    private_key: Option<String>,
    private_key_file: Option<String>,
    ckb_rpc_url: String,
    sudt_transfer_contract_type_script: json::Script,
    /// Sudt name to sudt type script map.
    #[serde(default)]
    sudt: HashMap<String, json::Script>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let config = fs::read_to_string(cli.config).context("reading config file")?;
    let config: Config = toml::from_str(&config).context("parsing config file")?;

    if config.private_key.is_some() && config.private_key_file.is_some() {
        bail!("invalid config: both private_key and private_key_file are present");
    }

    let key = if let Some(ref k) = config.private_key {
        hex::decode(k).context("hex decoding private key")?
    } else if let Some(ref kf) = config.private_key_file {
        fs::read(kf).context("reading private key file")?
    } else {
        let k = std::env::var("SUDT_TRANSFER_PRIVATE_KEY")
            .context("private key is not specified in config or the SUDT_TRANSFER_PRIVATE_KEY environment variable")?;
        hex::decode(k).context("hex decoding private key")?
    };
    let sk = secp256k1::SecretKey::from_slice(&key)
        .context("decoding private key (private key should be 32-byte long)")?;

    let secp = Secp256k1::new();
    let pubkey = secp256k1::PublicKey::from_secret_key(&secp, &sk);

    let address = AddressPayload::from_pubkey(&pubkey);
    let sender_lock_script = packed::Script::from(&address);

    println!(
        "port: {}",
        hex::encode(
            config
                .sdk_config
                .module_lock_script()
                .calc_script_hash()
                .as_slice()
        )
    );

    ensure!(
        config.sdk_config.module_lock_script().code_hash()
            == packed::Script::from(config.sudt_transfer_contract_type_script.clone())
                .calc_script_hash(),
        "port id code hash is not sudt transfer contract type script hash",
    );

    match cli.command {
        Commands::Recv => receive(config, sk, sender_lock_script).await,
        Commands::CreateStCell { sudt } => {
            create_st_cell(config, sk, sender_lock_script, sudt).await
        }
        Commands::ConsumeAck => consume_ack(config, sk, sender_lock_script).await,
        Commands::Send {
            sudt,
            receiver,
            amount,
        } => send(config, sk, sender_lock_script, sudt, receiver, amount).await,
    }
}

async fn consume_ack(
    config: Config,
    sk: secp256k1::SecretKey,
    sender_lock_script: packed::Script,
) -> Result<()> {
    let client = CkbRpcClient::new(config.ckb_rpc_url.clone());
    let sender = sender_lock_script.calc_script_hash().as_bytes().slice(..20);

    let mut ack_packets = pin!(
        PacketCell::subscribe(client.clone(), config.sdk_config.clone())
            .try_filter(|cell| futures::future::ready(cell.is_ack_packet()))
    );
    // Filter for a packet that is sent to us.
    let (p, pd) = loop {
        let p = ack_packets.try_next().await?.context("no packet cell")?;
        let pd = FungibleTokenPacketData::decode(&p.packet.packet.data[..])?;
        if pd.sender == sender {
            if p.packet.ack.as_deref() != Some(&[1]) {
                println!("skipping packet {pd}");
                continue;
            }
            break (p, pd);
        } else {
            println!("skipping packet {pd}");
        }
    };
    println!("consuming packet ack\n{pd}\n{:?}", p.packet.packet);

    let sudt_type_hash = hex::decode(pd.denom).context("decode base denom")?;
    let (sudt_transfer_dep, st_cell, st_cell_amount, _) =
        get_st_cell_by_sudt_type_hash(&client, &config, sudt_type_hash).await?;
    let sudt_dep = get_type_dep_from_cell(&client, &st_cell)
        .await
        .context("get sudt dep")?;

    let user_input = get_capacity_input(&client, &sender_lock_script).await?;

    let packet_contract_cell = get_latest_cell_by_type_script(
        &client,
        config.sdk_config.packet_contract_type_script().into(),
    )
    .await?;

    let (tx, envelope) = assemble_consume_ack_packet_partial_transaction(
        simple_dep(packet_contract_cell.out_point.into()),
        p,
    )?;
    // sighash placeholder witness.
    let placeholder_witness = packed::WitnessArgs::new_builder()
        .lock(Some(Bytes::from_static(&[0u8; 65])).pack())
        .build();
    let tx = tx
        .input(simple_input(st_cell.out_point.into()))
        .output(packed::CellOutput::from(st_cell.output))
        .output_data(sudt_amount_data(st_cell_amount).pack())
        .witness([].pack())
        .cell_dep(sudt_transfer_dep)
        .cell_dep(sudt_dep)
        // capacity input and witness.
        .input(simple_input(user_input.out_point.into()))
        .witness(placeholder_witness.as_bytes().pack());
    let tx = add_ibc_envelope(tx, &envelope).build();
    let tx = complete_tx(&config.ckb_rpc_url, &tx, sender_lock_script, sk)?;
    send_transaction(&config.ckb_rpc_url, tx)?;

    Ok(())
}

fn get_sudt_type_script(config: &Config, sudt: &str) -> Result<packed::Script> {
    if sudt.trim_start().starts_with('{') {
        let sudt: json::Script = serde_json::from_str(sudt).context("parsing sudt type script")?;
        Ok(sudt.into())
    } else {
        Ok(config
            .sudt
            .get(sudt)
            .with_context(|| format!("sudt {sudt} not found in config file"))?
            .clone()
            .into())
    }
}

async fn create_st_cell(
    config: Config,
    sk: secp256k1::SecretKey,
    sender_lock_script: packed::Script,
    sudt: String,
) -> Result<()> {
    let client = CkbRpcClient::new(config.ckb_rpc_url.clone());

    let sudt_type_script = get_sudt_type_script(&config, &sudt)?;

    let st_cell_lock_script = config.sdk_config.module_lock_script();

    let a_sudt_cell = get_latest_cell_by_type_script(&client, sudt_type_script.clone().into())
        .await
        .context("get sudt cell to get cell dep")?;
    let sudt_dep = get_type_dep_from_cell(&client, &a_sudt_cell)
        .await
        .context("get sudt cell dep")?;

    let tx = TransactionView::new_advanced_builder()
        .output(
            packed::CellOutput::new_builder()
                .lock(st_cell_lock_script)
                .type_(Some(sudt_type_script).pack())
                .build_exact_capacity(Capacity::bytes(16).unwrap())
                .unwrap(),
        )
        .output_data(sudt_amount_data(0).pack())
        .cell_dep(sudt_dep)
        .build();

    let tx = complete_tx(&config.ckb_rpc_url, &tx, sender_lock_script, sk)?;
    send_transaction(&config.ckb_rpc_url, tx)?;

    Ok(())
}

async fn send(
    config: Config,
    sk: secp256k1::SecretKey,
    sender_lock_script: packed::Script,
    sudt: String,
    receiver: String,
    amount: u128,
) -> Result<()> {
    let client = CkbRpcClient::new(config.ckb_rpc_url.clone());

    let sudt_type_script = get_sudt_type_script(&config, &sudt)?;

    // Search st-cell.
    let sudt_transfer_dep = simple_dep(
        get_latest_cell_by_type_script(&client, config.sudt_transfer_contract_type_script.clone())
            .await?
            .out_point
            .into(),
    );
    let st_cell_lock_script = config.sdk_config.module_lock_script();
    let sudt_search_filter = ckb_indexer::SearchKeyFilter {
        script: Some(sudt_type_script.clone().into()),
        script_len_range: {
            // script_len is caculated by (code_hash + hash_type + args).len
            let tl = sudt_type_script.args().raw_data().len() as u64 + 33;
            Some([tl.into(), (tl + 1).into()])
        },
        output_data_len_range: Some([16.into(), 17.into()]),
        ..Default::default()
    };
    let mut st_cells = client
        .get_cells(
            ckb_indexer::SearchKey {
                filter: Some(sudt_search_filter.clone()),
                group_by_transaction: Some(true),
                script: st_cell_lock_script.clone().into(),
                script_search_mode: Some(ckb_indexer::ScriptSearchMode::Exact),
                script_type: ckb_indexer::ScriptType::Lock,
                with_data: Some(true),
            },
            ckb_indexer::Order::Desc,
            1.into(),
            None,
        )
        .await?;
    ensure!(!st_cells.objects.is_empty(), "no st-cell found");
    let st_cell = st_cells.objects.remove(0);
    let st_cell_amount = u128::from_le_bytes(
        st_cell
            .output_data
            .as_ref()
            .unwrap()
            .as_bytes()
            .try_into()
            .unwrap(),
    );

    let sudt_dep = get_type_dep_from_cell(&client, &st_cell)
        .await
        .context("get sudt dep")?;

    // Search sudt cell.
    let cells = client
        .get_cells(
            ckb_indexer::SearchKey {
                filter: Some(sudt_search_filter),
                group_by_transaction: Some(true),
                script: sender_lock_script.clone().into(),
                script_search_mode: Some(ckb_indexer::ScriptSearchMode::Exact),
                script_type: ckb_indexer::ScriptType::Lock,
                with_data: Some(true),
            },
            ckb_indexer::Order::Desc,
            10.into(),
            None,
        )
        .await?;
    let mut sudt_cells = Vec::new();
    let mut sudt_amount = 0u128;
    for c in cells.objects {
        let a = u128::from_le_bytes(
            c.output_data
                .as_ref()
                .unwrap()
                .as_bytes()
                .try_into()
                .unwrap(),
        );
        sudt_amount = sudt_amount.checked_add(a).context("amount overflow")?;
        sudt_cells.push(c);

        if sudt_amount >= amount {
            break;
        }
    }
    let sudt_change = sudt_amount
        .checked_sub(amount)
        .context("failed to collect enough sudt input")?;

    let axon_metadata_cell = get_latest_cell_by_type_script(
        &client,
        config.sdk_config.axon_metadata_type_script().into(),
    )
    .await?;
    let channel_contract_cell = get_latest_cell_by_type_script(
        &client,
        config.sdk_config.channel_contract_type_script().into(),
    )
    .await?;
    let channel = IbcChannelCell::get_latest(&client, &config.sdk_config).await?;
    let data = FungibleTokenPacketData {
        amount: amount.try_into().context("amount overflow")?,
        sender: sender_lock_script.calc_script_hash().as_bytes()[..20]
            .to_vec()
            .into(),
        receiver: hex::decode(receiver.strip_prefix("0x").unwrap_or(&receiver))
            .context("receiver")?
            .into(),
        denom: hex::encode(sudt_type_script.calc_script_hash().as_slice()),
    }
    .encode_to_vec();
    let (tx, envelope) = assemble_send_packet_partial_transaction(
        simple_dep(axon_metadata_cell.out_point.into()),
        simple_dep(channel_contract_cell.out_point.into()),
        &config.sdk_config,
        channel,
        data,
        0,
        0,
    )?;

    let mut tx = tx
        .input(simple_input(st_cell.out_point.into()))
        .output(packed::CellOutput::from(st_cell.output))
        .output_data(
            sudt_amount_data(
                st_cell_amount
                    .checked_add(amount)
                    .context("sudt amount overflow")?,
            )
            .pack(),
        )
        .cell_dep(sudt_transfer_dep.clone())
        .cell_dep(sudt_dep);

    let sudt_output = packed::CellOutput::from(sudt_cells[0].output.clone())
        .as_builder()
        .build_exact_capacity(Capacity::bytes(16).unwrap())
        .unwrap();
    for c in sudt_cells {
        tx = tx.input(simple_input(c.out_point.into()));
    }
    // sighash placeholder witness.
    let placeholder_witness = packed::WitnessArgs::new_builder()
        .lock(Some(Bytes::from_static(&[0u8; 65])).pack())
        .build();
    tx = tx.witness(placeholder_witness.as_bytes().pack());

    // SUDT change output.
    let tx = tx
        .output(sudt_output)
        .output_data(sudt_amount_data(sudt_change).pack());

    let tx = add_ibc_envelope(tx, &envelope).build();

    let tx = complete_tx(&config.ckb_rpc_url, &tx, sender_lock_script.clone(), sk)?;

    send_transaction(&config.ckb_rpc_url, tx)?;

    println!("consuming ack");

    consume_ack(config, sk, sender_lock_script).await?;

    Ok(())
}

async fn receive(
    config: Config,
    sk: secp256k1::SecretKey,
    receiver_lock_script: packed::Script,
) -> Result<()> {
    let client = CkbRpcClient::new(config.ckb_rpc_url.clone());
    let receiver = receiver_lock_script
        .calc_script_hash()
        .as_bytes()
        .slice(..20);

    let mut recv_packets = pin!(
        PacketCell::subscribe(client.clone(), config.sdk_config.clone())
            .try_filter(|cell| futures::future::ready(cell.is_recv_packet()))
    );
    // Filter for a packet that is sent to us.
    let (p, pd) = loop {
        let p = recv_packets
            .try_next()
            .await?
            .context("no packet cell for us")?;
        let pd = FungibleTokenPacketData::decode(&p.packet.packet.data[..])?;
        if pd.receiver == receiver {
            break (p, pd);
        } else {
            println!("skipping packet {pd}");
        }
    };
    println!("receiving packet\n{pd}\n{:?}", p.packet.packet);

    let base_denom = pd.denom.split('/').last().context("get base denom")?;
    let sudt_type_hash = hex::decode(base_denom).context("decode base denom")?;

    let (sudt_transfer_dep, st_cell, st_cell_amount, sudt_type_script) =
        get_st_cell_by_sudt_type_hash(&client, &config, sudt_type_hash).await?;

    let sudt_dep = get_type_dep_from_cell(&client, &st_cell)
        .await
        .context("get sudt dep")?;

    let axon_metadata_cell = get_latest_cell_by_type_script(
        &client,
        config.sdk_config.axon_metadata_type_script().into(),
    )
    .await?;
    let channel_contract_cell = get_latest_cell_by_type_script(
        &client,
        config.sdk_config.channel_contract_type_script().into(),
    )
    .await?;
    let packet_contract_cell = get_latest_cell_by_type_script(
        &client,
        config.sdk_config.packet_contract_type_script().into(),
    )
    .await?;
    let channel = IbcChannelCell::get_latest(&client, &config.sdk_config).await?;

    let (tx, envelope) = assemble_write_ack_partial_transaction(
        simple_dep(axon_metadata_cell.out_point.into()),
        simple_dep(channel_contract_cell.out_point.into()),
        simple_dep(packet_contract_cell.out_point.into()),
        &config.sdk_config,
        channel,
        p,
        vec![1],
    )?;

    let user_input = get_capacity_input(&client, &receiver_lock_script).await?;

    // sighash placeholder witness.
    let placeholder_witness = packed::WitnessArgs::new_builder()
        .lock(Some(Bytes::from_static(&[0u8; 65])).pack())
        .build();
    let tx = tx
        // st-cell input/output.
        .input(simple_input(st_cell.out_point.into()))
        .output(packed::CellOutput::from(st_cell.output))
        .output_data(
            sudt_amount_data(
                st_cell_amount
                    .checked_sub(pd.amount.into())
                    .context("st-cell amount not enough")?,
            )
            .pack(),
        )
        .witness([].pack())
        .cell_dep(sudt_transfer_dep.clone())
        .cell_dep(sudt_dep)
        // sudt output.
        .output(
            packed::CellOutput::new_builder()
                .lock(receiver_lock_script.clone())
                .type_(Some(sudt_type_script).pack())
                .build_exact_capacity(Capacity::bytes(16).unwrap())
                .unwrap(),
        )
        .output_data(sudt_amount_data(pd.amount.into()).pack())
        // capacity input and witness.
        .input(simple_input(user_input.out_point.into()))
        .witness(placeholder_witness.as_bytes().pack());

    let tx = add_ibc_envelope(tx, &envelope).build();

    let tx = complete_tx(&config.ckb_rpc_url, &tx, receiver_lock_script, sk)?;

    send_transaction(&config.ckb_rpc_url, tx)?;

    Ok(())
}

async fn get_capacity_input(
    client: &CkbRpcClient,
    user_lock_script: &packed::Script,
) -> Result<Cell> {
    let user_input = client
        .get_cells(
            ckb_indexer::SearchKey {
                filter: Some(ckb_indexer::SearchKeyFilter {
                    script_len_range: Some([0.into(), 1.into()]),
                    output_data_len_range: Some([0.into(), 1.into()]),
                    ..Default::default()
                }),
                group_by_transaction: Some(true),
                script: user_lock_script.clone().into(),
                script_search_mode: Some(ckb_indexer::ScriptSearchMode::Exact),
                script_type: ckb_indexer::ScriptType::Lock,
                with_data: Some(true),
            },
            ckb_indexer::Order::Desc,
            1.into(),
            None,
        )
        .await?
        .objects
        .into_iter()
        .next()
        .context("get user input cell")?;
    Ok(user_input)
}

/// Returns (sudt_transfer_dep, st_cell, st_cell_amount, sudt_type_script).
async fn get_st_cell_by_sudt_type_hash(
    client: &CkbRpcClient,
    config: &Config,
    sudt_type_hash: Vec<u8>,
) -> Result<(packed::CellDep, Cell, u128, packed::Script), anyhow::Error> {
    let sudt_transfer_dep = simple_dep(
        get_latest_cell_by_type_script(client, config.sudt_transfer_contract_type_script.clone())
            .await?
            .out_point
            .into(),
    );
    let st_cell_lock_script = config.sdk_config.module_lock_script();
    let st_cells = client
        .get_cells(
            ckb_indexer::SearchKey {
                filter: None,
                group_by_transaction: Some(true),
                script: st_cell_lock_script.clone().into(),
                script_search_mode: Some(ckb_indexer::ScriptSearchMode::Exact),
                script_type: ckb_indexer::ScriptType::Lock,
                with_data: Some(true),
            },
            ckb_indexer::Order::Desc,
            500.into(),
            None,
        )
        .await?;
    let st_cell = st_cells
        .objects
        .into_iter()
        .find(|c| {
            c.output.type_.as_ref().is_some_and(|t| {
                packed::Script::from(t.clone())
                    .calc_script_hash()
                    .as_slice()
                    == sudt_type_hash
            })
        })
        .context("cannot find st-cell")?;
    let st_cell_amount = u128::from_le_bytes(
        st_cell
            .output_data
            .as_ref()
            .unwrap()
            .as_bytes()
            .try_into()
            .unwrap(),
    );
    let sudt_type_script = packed::Script::from(st_cell.output.type_.as_ref().unwrap().clone());
    Ok((sudt_transfer_dep, st_cell, st_cell_amount, sudt_type_script))
}

/// Get cell dep for the type script of the cell.
///
/// The dep must be of DepType::Code in the transaction the creates this cell.
async fn get_type_dep_from_cell(client: &CkbRpcClient, cell: &Cell) -> Result<packed::CellDep> {
    let cell_type = cell.output.type_.clone().context("get type script")?;
    ensure!(cell_type.hash_type == json::ScriptHashType::Type);
    let expected_type_hash = cell_type.code_hash;
    let tx = client
        .get_transaction(cell.out_point.tx_hash.clone())
        .await?
        .transaction
        .context("get transaction")?;
    for d in tx.inner.cell_deps {
        if d.dep_type != json::DepType::Code {
            continue;
        }
        let tx = client
            .get_transaction(d.out_point.tx_hash.clone())
            .await?
            .transaction
            .context("get transaction")?;
        let _type = tx
            .inner
            .outputs
            .get(d.out_point.index.value() as usize)
            .context("get output")?
            .type_
            .clone();
        let _type = match _type {
            Some(_type) => _type,
            None => continue,
        };
        if packed::Script::from(_type).calc_script_hash().unpack() == expected_type_hash {
            return Ok(d.into());
        }
    }

    bail!("cannot find a matching cell dep")
}

fn simple_input(o: packed::OutPoint) -> packed::CellInput {
    packed::CellInput::new_builder().previous_output(o).build()
}

fn simple_dep(o: packed::OutPoint) -> packed::CellDep {
    packed::CellDep::new_builder().out_point(o).build()
}

fn sudt_amount_data(amount: u128) -> Bytes {
    Bytes::copy_from_slice(&amount.to_le_bytes()[..])
}

#[derive(Message)]
pub struct FungibleTokenPacketData {
    /// hex(sudt type script)
    #[prost(string, tag = "1")]
    pub denom: String,
    /// SUDT amount.
    #[prost(uint64, tag = "2")]
    pub amount: u64,
    /// For ckb address, this should be ckb_blake2b(packed lock script)[..20]
    #[prost(bytes, tag = "3")]
    pub sender: Bytes,
    /// For ckb address, this should be ckb_blake2b(packed lock script)[..20]
    #[prost(bytes, tag = "4")]
    pub receiver: Bytes,
}

impl fmt::Display for FungibleTokenPacketData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FungibleTokenPacketData")
            .field("denom", &self.denom)
            .field("amount", &self.amount)
            .field("sender", &format_args!("{:#x}", self.sender))
            .field("receiver", &format_args!("{:#x}", self.receiver))
            .finish()
    }
}

/// Balance and sign tx. The sighash dep will be added. This won't add any new
/// witnesses if there's already a placeholder witness.
fn complete_tx(
    ckb_rpc: &str,
    tx: &TransactionView,
    sender: packed::Script,
    sender_key: secp256k1::SecretKey,
) -> Result<TransactionView> {
    block_in_place(|| complete_tx_inner(ckb_rpc, tx, sender, sender_key))
}

fn complete_tx_inner(
    ckb_rpc: &str,
    tx: &TransactionView,
    sender: packed::Script,
    sender_key: secp256k1::SecretKey,
) -> Result<TransactionView> {
    // Build ScriptUnlocker
    let signer = SecpCkbRawKeySigner::new_with_secret_keys(vec![sender_key]);
    let sighash_unlocker = SecpSighashUnlocker::from(Box::new(signer) as Box<_>);
    let sighash_script_id = ScriptId::new_type(SIGHASH_TYPE_HASH.clone());
    let mut unlockers = HashMap::default();
    unlockers.insert(
        sighash_script_id,
        Box::new(sighash_unlocker) as Box<dyn ScriptUnlocker>,
    );

    // Build CapacityBalancer
    let placeholder_witness = packed::WitnessArgs::new_builder()
        .lock(Some(Bytes::from_static(&[0u8; 65])).pack())
        .build();
    let mut balancer = CapacityBalancer::new_simple(sender, placeholder_witness, 1000);

    // Build:
    //   * CellDepResolver
    //   * HeaderDepResolver
    //   * CellCollector
    //   * TransactionDependencyProvider
    let ckb_client = ckb_sdk::CkbRpcClient::new(ckb_rpc);
    let cell_dep_resolver = {
        let genesis_block = ckb_client.get_block_by_number(0.into())?.unwrap();
        DefaultCellDepResolver::from_genesis(&genesis_block.into())?
    };
    let header_dep_resolver = DefaultHeaderDepResolver::new(ckb_rpc);
    let mut cell_collector = DefaultCellCollector::new(ckb_rpc);
    let tx_dep_provider = DefaultTransactionDependencyProvider::new(ckb_rpc, 10);

    // Add sighash dep manually because the balancer may not add it if the tx
    // already have inputs from sender.
    let sighash = cell_dep_resolver.sighash_dep().unwrap().0.clone();
    let tx = tx.as_advanced_builder().cell_dep(sighash).build();

    let tx = balancer.balance_tx_capacity(
        &tx,
        &mut cell_collector,
        &tx_dep_provider,
        &cell_dep_resolver,
        &header_dep_resolver,
    )?;

    // Remove tailing empty witnesses.
    let mut ws = Vec::from_iter(tx.witnesses());
    while !ws.is_empty() && ws[ws.len() - 1].is_empty() {
        ws.pop();
    }
    let tx = tx.as_advanced_builder().set_witnesses(ws).build();

    let (tx, _) = unlock_tx(tx, &tx_dep_provider, &unlockers)?;

    Ok(tx)
}

fn send_transaction(url: &str, tx: TransactionView) -> Result<[u8; 32]> {
    block_in_place(|| send_transaction_inner(url, tx))
}

fn send_transaction_inner(url: &str, tx: TransactionView) -> Result<[u8; 32]> {
    let client = ckb_sdk::CkbRpcClient::new(url);
    let tx: json::Transaction = tx.data().into();
    let tx_hash = client
        .send_transaction(tx.clone(), Some(json::OutputsValidator::Passthrough))
        .map_err(|e| {
            println!(
                "Transaction: {}",
                serde_json::to_string_pretty(&tx).unwrap()
            );
            e
        })?;
    println!("sent transaction {tx_hash}");
    loop {
        let res = client.get_transaction_status(tx_hash.clone())?;
        match res.tx_status.status {
            json::Status::Committed => break,
            json::Status::Rejected => {
                bail!("transaction rejected, reason: {:?}", res.tx_status.reason)
            }
            json::Status::Unknown => {
                println!("transaction unknown, sending again");
                client
                    .send_transaction(tx.clone(), Some(json::OutputsValidator::Passthrough))
                    .map_err(|e| {
                        println!(
                            "Transaction: {}",
                            serde_json::to_string_pretty(&res).unwrap()
                        );
                        e
                    })?;
                println!("sent transaction {tx_hash}");
            }
            _ => {
                println!("transaction is {:?}", res.tx_status.status);
            }
        }
        std::thread::sleep(Duration::from_secs(5));
    }
    println!("transaction committed {tx_hash}");
    Ok(tx_hash.0)
}
