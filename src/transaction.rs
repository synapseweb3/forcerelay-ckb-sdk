use anyhow::{ensure, Result};
use ckb_hash::blake2b_256;
use ckb_ics_axon::{handler::IbcPacket, message::Envelope};
use ckb_types::{
    core::{Capacity, TransactionBuilder, TransactionView},
    packed,
    prelude::{Builder, Entity, Pack},
};

use crate::{
    config::Config,
    search::{IbcChannelCell, PacketCell},
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
/// You'd need to add [an IBC envelope](`add_ibc_envelope`) witness after other
/// witnesses yourself.
///
/// This is a pure function.
pub fn assemble_send_packet_partial_transaction(
    axon_metadata_cell_dep: packed::CellDep,
    channel_contract_cell_dep: packed::CellDep,
    config: &Config,
    channel: IbcChannelCell,
    // Sequence will be overwritten.
    mut packet: IbcPacket,
) -> Result<TransactionBuilder> {
    // XXX: is this correct?
    packet.packet.sequence = channel.channel.sequence.next_sequence_sends;
    let mut new_channel_state = channel.channel.clone();
    // XXX: overflow.
    new_channel_state.sequence.next_sequence_sends += 1;

    let prev_channel_bytes = rlp::encode(&channel.channel).freeze();
    let new_channel_bytes = rlp::encode(&new_channel_state).freeze();
    let channel_witness = packed::WitnessArgs::new_builder()
        .input_type(Some(prev_channel_bytes).pack())
        .output_type(Some(new_channel_bytes.clone()).pack())
        .build();

    let packet_bytes = rlp::encode(&packet).freeze();
    let packet_cell = packed::CellOutput::new_builder()
        .lock(config.packet_cell_lock_script(packet.packet.sequence))
        .build_exact_capacity(Capacity::bytes(32)?)?;
    let packet_witness = packed::WitnessArgs::new_builder()
        .output_type(Some(packet_bytes.clone()).pack())
        .build();

    let tx = TransactionView::new_advanced_builder()
        .cell_dep(axon_metadata_cell_dep)
        .cell_dep(channel_contract_cell_dep)
        // Channel.
        .input(channel.as_input())
        // Same output (capacity and lock) as previous channel cell.
        .output(channel.output)
        .output_data(blake2b_256(&new_channel_bytes)[..].pack())
        .witness(channel_witness.as_bytes().pack())
        // Packet.
        .output(packet_cell)
        .output_data(blake2b_256(&packet_bytes)[..].pack())
        .witness(packet_witness.as_bytes().pack());

    Ok(tx)
}

/// Assemble WriteAck partial transaction. It'll have channel
/// input/output/witness, packet input/output/witness and all the cell deps
/// passed in.
///
/// You'd need to add [an IBC envelope](`add_ibc_envelope`) witness after other
/// witnesses yourself.
///
/// This is a pure function.
pub fn assemble_write_ack_partial_transaction(
    axon_metadata_cell_dep: packed::CellDep,
    channel_contract_cell_dep: packed::CellDep,
    packet_contract_cell_dep: packed::CellDep,
    config: &Config,
    channel: IbcChannelCell,
    packet: PacketCell,
    ack: IbcPacket,
) -> Result<TransactionBuilder> {
    ensure!(packet.is_recv_packet());
    // XXX: is this correct?
    ensure!(packet.packet.packet.sequence == ack.packet.sequence);
    ensure!(ack.packet.sequence == channel.channel.sequence.next_sequence_acks);

    let mut new_channel_state = channel.channel.clone();
    // XXX: is this correct?
    new_channel_state.sequence.next_sequence_acks += 1;

    let prev_channel_bytes = rlp::encode(&channel.channel).freeze();
    let new_channel_bytes = rlp::encode(&new_channel_state).freeze();
    let channel_witness = packed::WitnessArgs::new_builder()
        .input_type(Some(prev_channel_bytes).pack())
        .output_type(Some(new_channel_bytes.clone()).pack())
        .build();

    let prev_packet_bytes = rlp::encode(&packet.packet).freeze();
    let packet_bytes = rlp::encode(&ack).freeze();
    let packet_cell = packed::CellOutput::new_builder()
        // XXX: is this correct?
        .lock(config.packet_cell_lock_script(ack.packet.sequence))
        // XXX: is this correct?
        .build_exact_capacity(Capacity::bytes(32)?)?;
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
        .output(channel.output)
        .output_data(blake2b_256(&new_channel_bytes)[..].pack())
        .witness(channel_witness.as_bytes().pack())
        // Packet.
        .input(packet.as_input())
        .output(packet_cell)
        .output_data(blake2b_256(&packet_bytes)[..].pack())
        .witness(packet_witness.as_bytes().pack());

    Ok(tx)
}

/// Assemble consume AckPacket partial transaction. It'll have packet
/// input/witness and packet contract cell dep.
pub fn assemble_consume_ack_packet_partial_transaction(
    packet_contract_cell_dep: packed::CellDep,
    ack_packet_cell: PacketCell,
) -> Result<TransactionBuilder> {
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

    Ok(tx)
}
