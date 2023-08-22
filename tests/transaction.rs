use anyhow::Result;
use axon_types::metadata::Metadata;
use bytes::Bytes;
use ckb_ics_axon::{
    handler::{IbcChannel, IbcPacket, PacketStatus},
    message::{Envelope, MsgType},
    object::{Packet, State},
};
use ckb_jsonrpc_types::TransactionView;
use ckb_testtool::context::Context;
use ckb_types::{
    core::Capacity,
    packed,
    prelude::{Builder, Entity, Unpack},
};
use forcerelay_ckb_sdk::{
    config::{AddressOrScript, Config},
    search::{IbcChannelCell, PacketCell},
    transaction::{
        add_ibc_envelope, assemble_send_packet_partial_transaction,
        assemble_write_ack_partial_transaction,
    },
    utils::keccak256,
};

#[test]
fn test_send_packet() -> Result<()> {
    let mut context = Context::default();

    let axon_metadata_data = Metadata::new_builder().build().as_bytes();
    let axon_metadata_cell = context.deploy_cell(axon_metadata_data);
    let axon_metadata_type_script = context
        .get_cell(&axon_metadata_cell)
        .unwrap()
        .0
        .type_()
        .to_opt()
        .unwrap();
    let axon_metadata_cell_dep = packed::CellDep::new_builder()
        .out_point(axon_metadata_cell)
        .build();

    let channel_contract = context.deploy_cell(Bytes::from_static(include_bytes!(
        "../contracts/ics-channel"
    )));
    let channel_contract_type_id_args: [u8; 32] = context
        .get_cell(&channel_contract)
        .unwrap()
        .0
        .type_()
        .to_opt()
        .unwrap()
        .args()
        .as_reader()
        .raw_data()
        .try_into()
        .unwrap();
    let channel_contract_cell_dep = packed::CellDep::new_builder()
        .out_point(channel_contract)
        .build();

    let channel_id = 8;

    let config = Config {
        axon_metadata_type_script: AddressOrScript::Script(axon_metadata_type_script.into()),
        channel_contract_type_id_args: channel_contract_type_id_args.into(),
        channel_id,
        confirmations: 1,
        packet_contract_type_id_args: [0u8; 32].into(),
        user_lock_script: serde_json::from_str("\"ckt1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsqtp5rgl5262g5m2w7r9n4wc0wywsgvgk9cwc2mu8\"").unwrap(),
    };

    let current_channel_state = IbcChannel {
        number: channel_id,
        state: State::Open,
        port_id: config.port_id_string(),
        ..Default::default()
    };
    let current_channel_state_bytes = rlp::encode(&current_channel_state).freeze();
    let channel_output = packed::CellOutput::new_builder()
        .lock(config.channel_cell_lock_script())
        .build_exact_capacity(Capacity::bytes(32).unwrap())
        .unwrap();
    let channel_out_point = context.create_cell(
        channel_output.clone(),
        Bytes::copy_from_slice(&keccak256(&current_channel_state_bytes)),
    );
    let channel_cell = IbcChannelCell {
        channel: current_channel_state,
        out_point: channel_out_point.into(),
        output: channel_output.into(),
    };

    let packet = IbcPacket {
        packet: Packet {
            ..Default::default()
        },
        tx_hash: None,
        status: PacketStatus::Send,
    };

    let (tx, envelope) = assemble_send_packet_partial_transaction(
        axon_metadata_cell_dep,
        channel_contract_cell_dep,
        &config,
        channel_cell,
        packet,
    )?;
    let tx = add_ibc_envelope(tx, &envelope).build();

    // Test cell parsing.
    PacketCell::parse(tx.clone().into(), 1, &config)?;

    context.set_capture_debug(true);
    let r = context.verify_tx(&tx, u64::MAX);
    for m in context.captured_messages() {
        println!("{}", m.message);
    }
    r?;

    Ok(())
}

#[test]
fn test_write_ack_packet() -> Result<()> {
    let mut context = Context::default();

    let axon_metadata_data = Metadata::new_builder().build().as_bytes();
    let axon_metadata_cell = context.deploy_cell(axon_metadata_data);
    let axon_metadata_type_script = context
        .get_cell(&axon_metadata_cell)
        .unwrap()
        .0
        .type_()
        .to_opt()
        .unwrap();
    let axon_metadata_cell_dep = packed::CellDep::new_builder()
        .out_point(axon_metadata_cell)
        .build();

    let channel_contract = context.deploy_cell(Bytes::from_static(include_bytes!(
        "../contracts/ics-channel"
    )));
    let channel_contract_type_id_args: [u8; 32] = context
        .get_cell(&channel_contract)
        .unwrap()
        .0
        .type_()
        .to_opt()
        .unwrap()
        .args()
        .as_reader()
        .raw_data()
        .try_into()
        .unwrap();
    let channel_contract_cell_dep = packed::CellDep::new_builder()
        .out_point(channel_contract)
        .build();

    let packet_contract = context.deploy_cell(Bytes::from_static(include_bytes!(
        "../contracts/ics-packet"
    )));
    let packet_contract_type_id_args: [u8; 32] = context
        .get_cell(&packet_contract)
        .unwrap()
        .0
        .type_()
        .to_opt()
        .unwrap()
        .args()
        .as_reader()
        .raw_data()
        .try_into()
        .unwrap();
    let packet_contract_cell_dep = packed::CellDep::new_builder()
        .out_point(packet_contract)
        .build();

    let channel_id = 8;

    let config = Config {
        axon_metadata_type_script: AddressOrScript::Script(axon_metadata_type_script.into()),
        channel_contract_type_id_args: channel_contract_type_id_args.into(),
        channel_id,
        confirmations: 1,
        packet_contract_type_id_args: packet_contract_type_id_args.into(),
        user_lock_script: serde_json::from_str("\"ckt1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsqtp5rgl5262g5m2w7r9n4wc0wywsgvgk9cwc2mu8\"").unwrap(),
    };

    let current_channel_state = IbcChannel {
        number: channel_id,
        state: State::Open,
        port_id: config.port_id_string(),
        ..Default::default()
    };
    let current_channel_state_bytes = rlp::encode(&current_channel_state).freeze();
    let channel_output = packed::CellOutput::new_builder()
        .lock(config.channel_cell_lock_script())
        .build_exact_capacity(Capacity::bytes(32).unwrap())
        .unwrap();
    let channel_out_point = context.create_cell(
        channel_output.clone(),
        Bytes::copy_from_slice(&keccak256(&current_channel_state_bytes)),
    );
    let channel_cell = IbcChannelCell {
        channel: current_channel_state,
        out_point: channel_out_point.into(),
        output: channel_output.into(),
    };

    let packet = IbcPacket {
        packet: Packet {
            ..Default::default()
        },
        tx_hash: None,
        status: PacketStatus::Recv,
    };

    let packet_cell_out_point = context.create_cell(
        packed::CellOutput::new_builder()
            .lock(config.packet_cell_lock_script(0))
            .build(),
        Bytes::copy_from_slice(&keccak256(&rlp::encode(&packet))),
    );

    let packet_cell = PacketCell {
        channel: channel_cell.clone(),
        tx: TransactionView {
            hash: packet_cell_out_point.tx_hash().unpack(),
            // Invalid empty mock tx.
            inner: packed::Transaction::default().into(),
        },
        packet_cell_idx: packet_cell_out_point.index().unpack(),
        envelope: Envelope {
            msg_type: MsgType::MsgRecvPacket,
            // Invalid mock envelope content.
            content: vec![],
        },
        packet,
    };

    let (tx, envelope) = assemble_write_ack_partial_transaction(
        axon_metadata_cell_dep,
        channel_contract_cell_dep,
        packet_contract_cell_dep,
        &config,
        channel_cell,
        packet_cell,
        vec![],
    )?;
    let tx = add_ibc_envelope(tx, &envelope).build();

    // Test cell parsing.
    PacketCell::parse(tx.clone().into(), 1, &config)?;

    context.set_capture_debug(true);
    let r = context.verify_tx(&tx, u64::MAX);
    for m in context.captured_messages() {
        println!("{}", m.message);
    }
    r?;

    Ok(())
}
