use ckb_fixed_hash::H256;
use ckb_ics_axon::{
    handler::{IbcChannel, IbcPacket, PacketStatus, Sequence},
    message::{Envelope, MsgType},
    object::{ChannelCounterparty, Ordering, Packet, State},
};
use ckb_jsonrpc_types::JsonBytes;
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, DeserializeAs, SerializeAs};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JsonIbcPacket {
    #[serde(with = "JsonPacket")]
    pub packet: Packet,
    #[serde(with = "JsonPacketStatus")]
    pub status: PacketStatus,
    pub tx_hash: Option<H256>,
}

#[derive(Serialize, Deserialize)]
#[serde(remote = "PacketStatus")]
pub enum JsonPacketStatus {
    Send,
    Recv,
    WriteAck,
    Ack,
}

impl From<&IbcPacket> for JsonIbcPacket {
    fn from(value: &IbcPacket) -> Self {
        Self {
            packet: value.packet.clone(),
            status: value.status,
            tx_hash: value.tx_hash.map(|v| <[u8; 32]>::from(v).into()),
        }
    }
}

impl From<JsonIbcPacket> for IbcPacket {
    fn from(value: JsonIbcPacket) -> Self {
        Self {
            packet: value.packet,
            status: value.status,
            tx_hash: value.tx_hash.map(|v| <[u8; 32]>::from(v).into()),
        }
    }
}

#[serde_as]
#[derive(Serialize, Deserialize)]
#[serde(remote = "Packet", deny_unknown_fields)]
pub struct JsonPacket {
    pub sequence: u16,
    pub source_port_id: String,
    pub source_channel_id: String,
    pub destination_port_id: String,
    pub destination_channel_id: String,
    #[serde_as(as = "HexBytes")]
    pub data: Vec<u8>,
    pub timeout_height: u64,
    pub timeout_timestamp: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(remote = "IbcChannel", deny_unknown_fields)]
pub struct JsonIbcChannel {
    pub number: u16,
    pub port_id: String,
    #[serde(with = "JsonState")]
    pub state: State,
    #[serde(with = "JsonOrdering")]
    pub order: Ordering,
    #[serde(with = "JsonSequence")]
    pub sequence: Sequence,
    #[serde(with = "JsonChannelCounterparty")]
    pub counterparty: ChannelCounterparty,
    pub connection_hops: Vec<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(remote = "State")]
enum JsonState {
    Unknown,
    Init,
    OpenTry,
    Open,
    Closed,
    Frozen,
}

#[derive(Serialize, Deserialize)]
#[serde(remote = "Ordering")]
enum JsonOrdering {
    Unknown,
    Unordered,
    Ordered,
}

#[derive(Serialize, Deserialize)]
#[serde(remote = "Sequence", deny_unknown_fields)]
pub struct JsonSequence {
    pub next_sequence_sends: u16,
    pub next_sequence_recvs: u16,
    pub next_sequence_acks: u16,
    pub received_sequences: Vec<u16>,
}

#[derive(Serialize, Deserialize)]
#[serde(remote = "ChannelCounterparty", deny_unknown_fields)]
pub struct JsonChannelCounterparty {
    pub port_id: String,
    pub channel_id: String,
}

#[allow(clippy::enum_variant_names)]
#[derive(Serialize, Deserialize)]
#[serde(remote = "MsgType")]
enum JsonMsgType {
    MsgClientCreate,
    MsgClientUpdate,
    MsgClientMisbehaviour,
    MsgConnectionOpenInit,
    MsgConnectionOpenTry,
    MsgConnectionOpenAck,
    MsgConnectionOpenConfirm,
    MsgChannelOpenInit,
    MsgChannelOpenTry,
    MsgChannelOpenAck,
    MsgChannelOpenConfirm,
    MsgChannelCloseInit,
    MsgChannelCloseConfirm,
    MsgSendPacket,
    MsgRecvPacket,
    MsgWriteAckPacket,
    MsgAckPacket,
    MsgTimeoutPacket,
    MsgConsumeAckPacket,
}

#[serde_as]
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JsonEnvelope {
    #[serde(with = "JsonMsgType")]
    pub msg_type: MsgType,
    #[serde_as(as = "HexBytes")]
    pub content: Vec<u8>,
}

impl From<&Envelope> for JsonEnvelope {
    fn from(value: &Envelope) -> Self {
        Self {
            content: value.content.clone(),
            msg_type: value.msg_type,
        }
    }
}

impl From<JsonEnvelope> for Envelope {
    fn from(value: JsonEnvelope) -> Self {
        Self {
            msg_type: value.msg_type,
            content: value.content,
        }
    }
}

/// Just like JsonBytes but for using with serde_as.
pub struct HexBytes;

impl SerializeAs<Vec<u8>> for HexBytes {
    fn serialize_as<S>(source: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut hex = vec![0; 2 + source.len() * 2];
        hex[..2].copy_from_slice(b"0x");
        faster_hex::hex_encode(source, &mut hex[2..]).map_err(serde::ser::Error::custom)?;

        serializer.serialize_str(unsafe { std::str::from_utf8_unchecked(&hex) })
    }
}

impl<'de> DeserializeAs<'de, Vec<u8>> for HexBytes {
    fn deserialize_as<D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let b = JsonBytes::deserialize(deserializer)?;
        Ok(b.into_bytes().to_vec())
    }
}
