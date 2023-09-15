use anyhow::{ensure, Context, Result};
use ckb_ics_axon::{
    consts::PACKET_CELL_CAPACITY,
    get_channel_id_str,
    handler::{IbcPacket, PacketStatus},
    message::{Envelope, MsgConsumeAckPacket, MsgSendPacket, MsgType, MsgWriteAckPacket},
    object::Packet,
};
use ckb_types::{
    core::{Capacity, TransactionBuilder, TransactionView},
    packed,
    prelude::{Builder, Entity, Pack},
};

use crate::{
    config::Config,
    search::{IbcChannelCell, PacketCell},
    utils::keccak256,
};

pub fn add_ibc_envelope(tx: TransactionBuilder, envelope: &Envelope) -> TransactionBuilder {
    let envelope_bytes = rlp::encode(envelope).freeze();
    let envelope_witness = packed::WitnessArgs::new_builder()
        .output_type(Some(envelope_bytes).pack())
        .build();
    tx.witness(envelope_witness.as_bytes().pack())
}

/// Assemble SendPacket partial transaction. It'll have channel
/// input/output/witness, packet output/witness, axon metadata cell and channel
/// contract cell deps.
///
/// Sequence of the packet will be the next send sequence of the channel.
///
/// The envelope need to be [added](`add_ibc_envelope`) after other witnesses.
///
/// This is a pure function.
pub fn assemble_send_packet_partial_transaction(
    axon_metadata_cell_dep: packed::CellDep,
    channel_contract_cell_dep: packed::CellDep,
    config: &Config,
    channel: IbcChannelCell,
    data: Vec<u8>,
    timeout_height: u64,
    timeout_timestamp: u64,
) -> Result<(TransactionBuilder, Envelope)> {
    let packet = IbcPacket {
        tx_hash: None,
        status: PacketStatus::Send,
        packet: Packet {
            data,
            timeout_height,
            timeout_timestamp,
            sequence: channel.channel.sequence.next_sequence_sends,
            source_channel_id: get_channel_id_str(channel.channel.number),
            source_port_id: channel.channel.port_id.clone(),
            destination_port_id: channel.channel.counterparty.port_id.clone(),
            destination_channel_id: channel.channel.counterparty.channel_id.clone(),
        },
        ack: None,
    };
    let mut new_channel_state = channel.channel.clone();
    new_channel_state.sequence.next_sequence_sends = new_channel_state
        .sequence
        .next_sequence_sends
        .checked_add(1)
        .context("sequence overflow")?;

    let prev_channel_bytes = rlp::encode(&channel.channel).freeze();
    let new_channel_bytes = rlp::encode(&new_channel_state).freeze();
    let channel_witness = packed::WitnessArgs::new_builder()
        .input_type(Some(prev_channel_bytes).pack())
        .output_type(Some(new_channel_bytes.clone()).pack())
        .build();

    let packet_bytes = rlp::encode(&packet).freeze();
    let packet_cell = packed::CellOutput::new_builder()
        .lock(config.packet_cell_lock_script(packet.packet.sequence))
        .capacity(
            Capacity::bytes(PACKET_CELL_CAPACITY as usize)
                .unwrap()
                .pack(),
        )
        .build();
    let packet_witness = packed::WitnessArgs::new_builder()
        .output_type(Some(packet_bytes.clone()).pack())
        .build();

    let tx = TransactionView::new_advanced_builder()
        .cell_dep(axon_metadata_cell_dep)
        .cell_dep(channel_contract_cell_dep)
        // Channel.
        .input(channel.as_input())
        // Same output (capacity and lock) as previous channel cell.
        .output(channel.output.into())
        .output_data(keccak256(&new_channel_bytes)[..].pack())
        .witness(channel_witness.as_bytes().pack())
        // Packet.
        .output(packet_cell)
        .output_data(keccak256(&packet_bytes)[..].pack())
        .witness(packet_witness.as_bytes().pack());

    let envelope = Envelope {
        msg_type: MsgType::MsgSendPacket,
        content: rlp::encode(&MsgSendPacket {}).to_vec(),
    };

    Ok((tx, envelope))
}

/// Assemble WriteAck partial transaction. It'll have channel
/// input/output/witness, packet input/output/witness and all the cell deps
/// passed in.
///
/// The ack_message parameter would be put in the message envelope.
///
/// The envelope need to be [added](`add_ibc_envelope`) after other witnesses.
///
/// This is a pure function.
pub fn assemble_write_ack_partial_transaction(
    axon_metadata_cell_dep: packed::CellDep,
    channel_contract_cell_dep: packed::CellDep,
    packet_contract_cell_dep: packed::CellDep,
    config: &Config,
    channel: IbcChannelCell,
    packet: PacketCell,
    ack: Vec<u8>,
) -> Result<(TransactionBuilder, Envelope)> {
    ensure!(packet.is_recv_packet());

    let ack = IbcPacket {
        packet: packet.packet.packet.clone(),
        status: PacketStatus::WriteAck,
        tx_hash: None,
        ack: Some(ack),
    };

    let new_channel_state = channel.channel.clone();

    let prev_channel_bytes = rlp::encode(&channel.channel).freeze();
    let new_channel_bytes = rlp::encode(&new_channel_state).freeze();
    let channel_witness = packed::WitnessArgs::new_builder()
        .input_type(Some(prev_channel_bytes).pack())
        .output_type(Some(new_channel_bytes.clone()).pack())
        .build();

    let prev_packet_bytes = rlp::encode(&packet.packet).freeze();
    let packet_bytes = rlp::encode(&ack).freeze();
    let packet_cell = packed::CellOutput::new_builder()
        .lock(config.packet_cell_lock_script(ack.packet.sequence))
        .capacity(
            Capacity::bytes(PACKET_CELL_CAPACITY as usize)
                .unwrap()
                .pack(),
        )
        .build();
    let packet_witness = packed::WitnessArgs::new_builder()
        .input_type(Some(prev_packet_bytes).pack())
        .output_type(Some(packet_bytes.clone()).pack())
        .build();

    let tx = TransactionView::new_advanced_builder()
        .cell_dep(axon_metadata_cell_dep)
        .cell_dep(channel_contract_cell_dep)
        .cell_dep(packet_contract_cell_dep)
        // Channel.
        .input(channel.as_input())
        // Same output (capacity and lock) as previous channel cell.
        .output(channel.output.into())
        .output_data(keccak256(&new_channel_bytes)[..].pack())
        .witness(channel_witness.as_bytes().pack())
        // Packet.
        .input(packet.as_input())
        .output(packet_cell)
        .output_data(keccak256(&packet_bytes)[..].pack())
        .witness(packet_witness.as_bytes().pack());

    let envelope = Envelope {
        msg_type: MsgType::MsgWriteAckPacket,
        content: rlp::encode(&MsgWriteAckPacket {}).to_vec(),
    };

    Ok((tx, envelope))
}

/// Assemble consume AckPacket partial transaction. It'll have packet
/// input/witness and packet contract cell dep.
///
/// The envelope need to be [added](`add_ibc_envelope`) after other witnesses.
///
/// This is a pure function.
pub fn assemble_consume_ack_packet_partial_transaction(
    packet_contract_cell_dep: packed::CellDep,
    ack_packet_cell: PacketCell,
) -> Result<(TransactionBuilder, Envelope)> {
    ensure!(ack_packet_cell.is_ack_packet());

    let packet = ack_packet_cell;
    let prev_packet_bytes = rlp::encode(&packet.packet).freeze();
    let packet_witness = packed::WitnessArgs::new_builder()
        .input_type(Some(prev_packet_bytes).pack())
        .build();

    let tx = TransactionView::new_advanced_builder()
        .cell_dep(packet_contract_cell_dep)
        // Packet.
        .input(packet.as_input())
        .witness(packet_witness.as_bytes().pack());

    let envelope = Envelope {
        msg_type: MsgType::MsgConsumeAckPacket,
        content: rlp::encode(&MsgConsumeAckPacket {}).to_vec(),
    };

    Ok((tx, envelope))
}
