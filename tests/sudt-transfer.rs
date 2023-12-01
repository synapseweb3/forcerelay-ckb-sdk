use anyhow::Result;
use bytes::Bytes;
use ckb_ics_axon::{
    handler::{IbcChannel, IbcPacket, PacketStatus},
    message::{Envelope, MsgType},
    object::{Packet, State},
};
use ckb_jsonrpc_types::TransactionView;
use ckb_testtool::{builtin::ALWAYS_SUCCESS, context::Context};
use ckb_types::{core::Capacity, packed, prelude::*};
use forcerelay_ckb_sdk::{
    config::{AddressOrScript, Config},
    search::{IbcChannelCell, PacketCell},
    transaction::{
        add_ibc_envelope, assemble_consume_ack_packet_partial_transaction,
        assemble_send_packet_partial_transaction, assemble_write_ack_partial_transaction,
    },
    utils::keccak256,
};
use prost::Message;

const ZERO32: [u8; 32] = [0u8; 32];

#[test]
fn test_send_packet() -> Result<()> {
    let mut context = Context::default();

    let sudt_contract = context.deploy_cell(include_bytes!("../contracts/simple-udt")[..].into());
    let sudt_type_script = context
        .build_script_with_hash_type(
            &sudt_contract,
            ckb_types::core::ScriptHashType::Type,
            ZERO32[..].into(),
        )
        .unwrap();
    let sudt_type_script_hash = sudt_type_script.calc_script_hash().unpack().0;

    let always_success_contract = context.deploy_cell(ALWAYS_SUCCESS.clone());
    let always_success_lock = context
        .build_script(&always_success_contract, Bytes::new())
        .unwrap();
    let user_input_cell = context.create_cell(
        packed::CellOutput::new_builder()
            .lock(always_success_lock.clone())
            .type_(Some(sudt_type_script.clone()).pack())
            .build(),
        sudt_amount_data(100),
    );

    let sudt_transfer_args = Args {
        channel_contract_code_hash: &ZERO32,
        channel_id: 8,
        client_id: &ZERO32,
        packet_contract_code_hash: &ZERO32,
    }
    .encode();
    let sudt_transfer_contract =
        context.deploy_cell(include_bytes!("../contracts/ibc-sudt-transfer")[..].into());
    let sudt_transfer_lock = context
        .build_script(&sudt_transfer_contract, sudt_transfer_args.into())
        .unwrap();
    // SDUT Transfer cell amount 5000 -> 5100.
    let sudt_transfer_output = packed::CellOutput::new_builder()
        .lock(sudt_transfer_lock.clone())
        .type_(Some(sudt_type_script).pack())
        .build();
    let sudt_transfer_cell =
        context.create_cell(sudt_transfer_output.clone(), sudt_amount_data(5000));
    let sudt_transfer_output_data = sudt_amount_data(5100);

    // Send 100 SUDT from user to receiver.
    let data = FungibleTokenPacketData {
        denom: hex::encode(sudt_type_script_hash),
        amount: 100,
        sender: encode_addr(always_success_lock),
        receiver: b"receiver".to_vec(),
    }
    .encode_to_vec();

    let axon_metadata_data = Bytes::from_static(b"metadata");
    let axon_metadata_cell = context.deploy_cell(axon_metadata_data);
    let axon_metadata_type_script = get_type_script(&context, &axon_metadata_cell);
    let axon_metadata_cell_dep = simple_dep(axon_metadata_cell);

    let channel_contract = context.deploy_cell(Bytes::from_static(include_bytes!(
        "../contracts/ics-channel"
    )));
    let channel_contract_type_id_args: [u8; 32] = get_type_id_args(&context, &channel_contract);
    let channel_contract_cell_dep = simple_dep(channel_contract);

    let channel_id = 8;

    let config = Config {
        axon_metadata_type_script: AddressOrScript::Script(axon_metadata_type_script.into()),
        axon_ibc_handler_address: Default::default(),
        channel_contract_type_id_args: channel_contract_type_id_args.into(),
        channel_id,
        confirmations: 1,
        packet_contract_type_id_args: [0u8; 32].into(),
        module_lock_script: AddressOrScript::Script(sudt_transfer_lock.into()),
    };

    let current_channel_state = IbcChannel {
        number: channel_id,
        state: State::Open,
        port_id: config.port_id_string(),
        ..Default::default()
    };
    let current_channel_state_bytes = rlp::encode(&current_channel_state).freeze();
    let channel_output = packed::CellOutput::new_builder()
        .lock(config.channel_cell_lock_script(true))
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
        data,
        0,
        0,
    )?;
    let tx = tx
        .input(simple_input(sudt_transfer_cell))
        .input(simple_input(user_input_cell))
        .output(sudt_transfer_output)
        .output_data(sudt_transfer_output_data.pack());
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

#[test]
fn test_write_ack_packet() -> Result<()> {
    let mut context = Context::default();

    let sudt_contract = context.deploy_cell(include_bytes!("../contracts/simple-udt")[..].into());
    let sudt_type_script = context
        .build_script_with_hash_type(
            &sudt_contract,
            ckb_types::core::ScriptHashType::Type,
            ZERO32[..].into(),
        )
        .unwrap();
    let sudt_type_script_hash = sudt_type_script.calc_script_hash().unpack().0;

    let always_success_contract = context.deploy_cell(ALWAYS_SUCCESS.clone());
    let always_success_lock = context
        .build_script(&always_success_contract, Bytes::new())
        .unwrap();
    let user_input_cell = context.create_cell(
        packed::CellOutput::new_builder()
            .lock(always_success_lock.clone())
            .build(),
        Bytes::new(),
    );

    let axon_metadata_data = Bytes::from_static(b"metadata");
    let axon_metadata_cell = context.deploy_cell(axon_metadata_data);
    let axon_metadata_type_script = context
        .get_cell(&axon_metadata_cell)
        .unwrap()
        .0
        .type_()
        .to_opt()
        .unwrap();
    let axon_metadata_cell_dep = simple_dep(axon_metadata_cell);

    let channel_contract = context.deploy_cell(Bytes::from_static(include_bytes!(
        "../contracts/ics-channel"
    )));
    let channel_contract_type_id_args: [u8; 32] = get_type_id_args(&context, &channel_contract);
    let channel_contract_cell_dep = simple_dep(channel_contract);

    let packet_contract = context.deploy_cell(Bytes::from_static(include_bytes!(
        "../contracts/ics-packet"
    )));
    let packet_contract_type_id_args: [u8; 32] = get_type_id_args(&context, &packet_contract);
    let packet_contract_cell_dep = simple_dep(packet_contract);

    let channel_id = 8;

    let sudt_transfer_args = Args {
        channel_contract_code_hash: &ZERO32,
        channel_id: 8,
        client_id: &ZERO32,
        packet_contract_code_hash: &ZERO32,
    }
    .encode();
    let sudt_transfer_contract =
        context.deploy_cell(include_bytes!("../contracts/ibc-sudt-transfer")[..].into());
    let sudt_transfer_lock = context
        .build_script(&sudt_transfer_contract, sudt_transfer_args.into())
        .unwrap();
    // SDUT Transfer cell amount 5100 -> 5000.
    let sudt_transfer_output = packed::CellOutput::new_builder()
        .lock(sudt_transfer_lock.clone())
        .type_(Some(sudt_type_script).pack())
        .build();
    let sudt_transfer_cell =
        context.create_cell(sudt_transfer_output.clone(), sudt_amount_data(5100));
    let sudt_transfer_output_data = sudt_amount_data(5000);

    let config = Config {
        axon_metadata_type_script: AddressOrScript::Script(axon_metadata_type_script.into()),
        axon_ibc_handler_address: Default::default(),
        channel_contract_type_id_args: channel_contract_type_id_args.into(),
        channel_id,
        confirmations: 1,
        packet_contract_type_id_args: packet_contract_type_id_args.into(),
        module_lock_script: AddressOrScript::Script(sudt_transfer_lock.into()),
    };

    let current_channel_state = IbcChannel {
        number: channel_id,
        state: State::Open,
        port_id: config.port_id_string(),
        ..Default::default()
    };
    let current_channel_state_bytes = rlp::encode(&current_channel_state).freeze();
    let channel_output = packed::CellOutput::new_builder()
        .lock(config.channel_cell_lock_script(true))
        .build_exact_capacity(Capacity::bytes(32).unwrap())
        .unwrap();
    let channel_out_point = context.create_cell(
        channel_output.clone(),
        Bytes::copy_from_slice(&keccak256(&current_channel_state_bytes)),
    );
    let source_channel_id = current_channel_state.counterparty.channel_id.clone();
    let source_port_id = current_channel_state.counterparty.port_id.clone();
    let channel_cell = IbcChannelCell {
        channel: current_channel_state,
        out_point: channel_out_point.into(),
        output: channel_output.into(),
    };

    // Receiver 100 SUDT as user.
    let denom = format!(
        "{}/{}/{}",
        source_port_id,
        source_channel_id,
        hex::encode(sudt_type_script_hash)
    );
    let data = FungibleTokenPacketData {
        denom,
        amount: 100,
        sender: b"sender".to_vec(),
        receiver: encode_addr(always_success_lock),
    }
    .encode_to_vec();

    let packet = IbcPacket {
        packet: Packet {
            data,
            source_channel_id,
            source_port_id,
            ..Default::default()
        },
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
            // Mock empty commitments.
            commitments: vec![],
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
    let tx = tx
        .input(simple_input(user_input_cell))
        .input(simple_input(sudt_transfer_cell))
        .output(sudt_transfer_output)
        .output_data(sudt_transfer_output_data.pack());

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
    for success in [false, true] {
        let mut context = Context::default();

        let sudt_contract =
            context.deploy_cell(include_bytes!("../contracts/simple-udt")[..].into());
        let sudt_type_script = context
            .build_script_with_hash_type(
                &sudt_contract,
                ckb_types::core::ScriptHashType::Type,
                ZERO32[..].into(),
            )
            .unwrap();
        let sudt_type_script_hash = sudt_type_script.calc_script_hash().unpack().0;

        let always_success_contract = context.deploy_cell(ALWAYS_SUCCESS.clone());
        let always_success_lock = context
            .build_script(&always_success_contract, Bytes::new())
            .unwrap();
        let user_cell = context.create_cell(
            packed::CellOutput::new_builder()
                .lock(always_success_lock.clone())
                .build(),
            Bytes::new(),
        );

        let sudt_transfer_args = Args {
            channel_contract_code_hash: &ZERO32,
            channel_id: 8,
            client_id: &ZERO32,
            packet_contract_code_hash: &ZERO32,
        }
        .encode();
        let sudt_transfer_contract =
            context.deploy_cell(include_bytes!("../contracts/ibc-sudt-transfer")[..].into());
        let sudt_transfer_lock = context
            .build_script(&sudt_transfer_contract, sudt_transfer_args.into())
            .unwrap();
        let sudt_transfer_output = packed::CellOutput::new_builder()
            .lock(sudt_transfer_lock.clone())
            .type_(Some(sudt_type_script).pack())
            .build();
        let sudt_transfer_cell =
            context.create_cell(sudt_transfer_output.clone(), sudt_amount_data(5100));
        // Refund if not success.
        let sudt_transfer_output_data = sudt_amount_data(if success { 5100 } else { 5000 });

        let data = FungibleTokenPacketData {
            denom: hex::encode(sudt_type_script_hash),
            amount: 100,
            sender: encode_addr(always_success_lock.clone()),
            receiver: b"receiver".to_vec(),
        }
        .encode_to_vec();

        let packet_contract = context.deploy_cell(Bytes::from_static(include_bytes!(
            "../contracts/ics-packet"
        )));
        let packet_contract_type_id_args: [u8; 32] = get_type_id_args(&context, &packet_contract);
        let packet_contract_cell_dep = simple_dep(packet_contract);

        let channel_id = 8;

        let config = Config {
            // Invalid.
            axon_metadata_type_script: AddressOrScript::Script(always_success_lock.clone().into()),
            axon_ibc_handler_address: Default::default(),
            // Invalid.
            channel_contract_type_id_args: [0; 32].into(),
            channel_id,
            confirmations: 1,
            packet_contract_type_id_args: packet_contract_type_id_args.into(),
            module_lock_script: AddressOrScript::Script(sudt_transfer_lock.clone().into()),
        };

        let packet = IbcPacket {
            packet: Packet {
                data,
                ..Default::default()
            },
            status: PacketStatus::Ack,
            ack: Some(vec![if success { 1 } else { 0 }]),
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
                // Mock empty commitments.
                commitments: vec![],
            },
            packet,
        };

        let (tx, envelope) =
            assemble_consume_ack_packet_partial_transaction(packet_contract_cell_dep, packet_cell)?;
        let tx = tx
            .input(simple_input(user_cell))
            .input(simple_input(sudt_transfer_cell))
            .output(sudt_transfer_output)
            .output_data(sudt_transfer_output_data.pack());
        let tx = add_ibc_envelope(tx, &envelope).build();
        let tx = context.complete_tx(tx);

        context.set_capture_debug(true);
        let r = context.verify_tx(&tx, u64::MAX);
        for m in context.captured_messages() {
            println!("{}", m.message);
        }
        r?;
    }

    Ok(())
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

fn encode_addr(lock: packed::Script) -> Vec<u8> {
    lock.calc_script_hash().as_slice()[..20].to_vec()
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

pub struct Args<'a> {
    pub client_id: &'a [u8; 32],
    pub channel_id: u16,
    pub channel_contract_code_hash: &'a [u8; 32],
    pub packet_contract_code_hash: &'a [u8; 32],
}

impl<'a> Args<'a> {
    pub fn encode(&self) -> Vec<u8> {
        [
            self.client_id,
            &u16::to_be_bytes(self.channel_id)[..],
            self.channel_contract_code_hash,
            self.packet_contract_code_hash,
        ]
        .concat()
    }
}

/// FungibleTokenPacketData defines a struct for the packet payload
/// See FungibleTokenPacketData spec:
/// <https://github.com/cosmos/ibc/tree/master/spec/app/ics-020-fungible-token-transfer#data-structures>
#[derive(Message)]
pub struct FungibleTokenPacketData {
    /// hex(sudt type script)
    #[prost(string, tag = "1")]
    pub denom: String,
    /// SUDT amount.
    #[prost(uint64, tag = "2")]
    pub amount: u64,
    /// For ckb address, this should be abi.encodePacked(ckb_blake2b(packed lock script)[..20])
    #[prost(bytes, tag = "3")]
    pub sender: Vec<u8>,
    /// For ckb address, this should be abi.encodePacked(ckb_blake2b(packed lock script)[..20])
    #[prost(bytes, tag = "4")]
    pub receiver: Vec<u8>,
}
