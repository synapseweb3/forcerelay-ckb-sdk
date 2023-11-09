use anyhow::Result;
use axon_types::metadata::Metadata;
use bytes::Bytes;
use ckb_ics_axon::{
    handler::{IbcChannel, IbcPacket, PacketStatus},
    message::{Envelope, MsgType},
    object::{Packet, State},
};
use ckb_jsonrpc_types::TransactionView;
use ckb_testtool::{builtin::ALWAYS_SUCCESS, context::Context};
use ckb_types::{
    core::Capacity,
    packed,
    prelude::{Builder, Entity, Unpack},
};
use forcerelay_ckb_sdk::{
    config::{AddressOrScript, Config},
    search::{IbcChannelCell, PacketCell},
    transaction::{
        add_ibc_envelope, assemble_consume_ack_packet_partial_transaction,
        assemble_send_packet_partial_transaction, assemble_write_ack_partial_transaction,
    },
    utils::keccak256,
};

#[test]
fn test_send_packet() -> Result<()> {
    let mut context = Context::default();

    let always_success_contract = context.deploy_cell(ALWAYS_SUCCESS.clone());
    let always_success_lock = context
        .build_script(&always_success_contract, Bytes::new())
        .unwrap();
    let always_success_cell = context.create_cell(
        packed::CellOutput::new_builder()
            .lock(always_success_lock.clone())
            .build(),
        Bytes::new(),
    );

    let axon_metadata_data = Metadata::new_builder().build().as_bytes();
    let axon_metadata_cell = context.deploy_cell(axon_metadata_data);
    let axon_metadata_type_script = get_type_script(&context, &axon_metadata_cell);
    let axon_metadata_cell_dep = packed::CellDep::new_builder()
        .out_point(axon_metadata_cell)
        .build();

    let channel_contract = context.deploy_cell(Bytes::from_static(include_bytes!(
        "../contracts/ics-channel"
    )));
    let channel_contract_type_id_args: [u8; 32] = get_type_id_args(&context, &channel_contract);
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
        module_lock_script: AddressOrScript::Script(always_success_lock.into()),
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

    let (tx, envelope) = assemble_send_packet_partial_transaction(
        axon_metadata_cell_dep,
        channel_contract_cell_dep,
        &config,
        channel_cell,
        vec![],
        0,
        0,
    )?;
    let tx = tx.input(
        packed::CellInput::new_builder()
            .previous_output(always_success_cell)
            .build(),
    );
    let tx = add_ibc_envelope(tx, &envelope).build();
    let tx = context.complete_tx(tx);

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

    let always_success_contract = context.deploy_cell(ALWAYS_SUCCESS.clone());
    let always_success_lock = context
        .build_script(&always_success_contract, Bytes::new())
        .unwrap();
    let always_success_cell = context.create_cell(
        packed::CellOutput::new_builder()
            .lock(always_success_lock.clone())
            .build(),
        Bytes::new(),
    );

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
    let channel_contract_type_id_args: [u8; 32] = get_type_id_args(&context, &channel_contract);
    let channel_contract_cell_dep = packed::CellDep::new_builder()
        .out_point(channel_contract)
        .build();

    let packet_contract = context.deploy_cell(Bytes::from_static(include_bytes!(
        "../contracts/ics-packet"
    )));
    let packet_contract_type_id_args: [u8; 32] = get_type_id_args(&context, &packet_contract);
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
        module_lock_script: AddressOrScript::Script(always_success_lock.into()),
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
        ack: None,
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
        vec![1],
    )?;
    let tx = tx.input(
        packed::CellInput::new_builder()
            .previous_output(always_success_cell)
            .build(),
    );
    let tx = add_ibc_envelope(tx, &envelope).build();
    let tx = context.complete_tx(tx);

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
fn test_consume_ack_packet() -> Result<()> {
    let mut context = Context::default();

    let always_success_contract = context.deploy_cell(ALWAYS_SUCCESS.clone());
    let always_success_lock = context
        .build_script(&always_success_contract, Bytes::new())
        .unwrap();
    let always_success_cell = context.create_cell(
        packed::CellOutput::new_builder()
            .lock(always_success_lock.clone())
            .build(),
        Bytes::new(),
    );

    let packet_contract = context.deploy_cell(Bytes::from_static(include_bytes!(
        "../contracts/ics-packet"
    )));
    let packet_contract_type_id_args: [u8; 32] = get_type_id_args(&context, &packet_contract);
    let packet_contract_cell_dep = packed::CellDep::new_builder()
        .out_point(packet_contract)
        .build();

    let channel_id = 8;

    let config = Config {
        // Invalid.
        axon_metadata_type_script: AddressOrScript::Script(always_success_lock.clone().into()),
        // Invalid.
        channel_contract_type_id_args: [0; 32].into(),
        channel_id,
        confirmations: 1,
        packet_contract_type_id_args: packet_contract_type_id_args.into(),
        module_lock_script: AddressOrScript::Script(always_success_lock.into()),
    };

    let packet = IbcPacket {
        packet: Packet {
            ..Default::default()
        },
        tx_hash: None,
        status: PacketStatus::Ack,
        ack: Some(vec![1]),
    };

    let packet_cell_out_point = context.create_cell(
        packed::CellOutput::new_builder()
            .lock(config.packet_cell_lock_script(0))
            .build(),
        Bytes::copy_from_slice(&keccak256(&rlp::encode(&packet))),
    );

    let packet_cell = PacketCell {
        // Invalid.
        channel: IbcChannelCell {
            out_point: packed::OutPoint::default().into(),
            output: packed::CellOutput::default().into(),
            channel: IbcChannel::default(),
        },
        tx: TransactionView {
            hash: packet_cell_out_point.tx_hash().unpack(),
            // Invalid empty mock tx.
            inner: packed::Transaction::default().into(),
        },
        packet_cell_idx: packet_cell_out_point.index().unpack(),
        envelope: Envelope {
            msg_type: MsgType::MsgAckPacket,
            // Invalid mock envelope content.
            content: vec![],
        },
        packet,
    };

    let (tx, envelope) =
        assemble_consume_ack_packet_partial_transaction(packet_contract_cell_dep, packet_cell)?;
    let tx = tx.input(
        packed::CellInput::new_builder()
            .previous_output(always_success_cell)
            .build(),
    );
    let tx = add_ibc_envelope(tx, &envelope).build();
    let tx = context.complete_tx(tx);

    context.set_capture_debug(true);
    let r = context.verify_tx(&tx, u64::MAX);
    for m in context.captured_messages() {
        println!("{}", m.message);
    }
    r?;

    Ok(())
}

/// # Panics
///
/// If the out point doesn't exist.
fn get_type_script(context: &Context, out_point: &packed::OutPoint) -> packed::Script {
    context
        .get_cell(out_point)
        .unwrap()
        .0
        .type_()
        .to_opt()
        .unwrap()
}

/// # Panics
///
/// If the out point doesn't exist or if the args are not 32 bytes.
fn get_type_id_args(context: &Context, out_point: &packed::OutPoint) -> [u8; 32] {
    get_type_script(context, out_point)
        .args()
        .as_reader()
        .raw_data()
        .try_into()
        .unwrap()
}
