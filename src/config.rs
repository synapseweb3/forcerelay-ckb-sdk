mod types;

use ckb_fixed_hash::H256;
use ckb_ics_axon::{ChannelArgs, PacketArgs};
use ckb_sdk::constants::TYPE_ID_CODE_HASH;
use ckb_types::{
    core::ScriptHashType,
    packed,
    prelude::{Builder, Entity, Pack, Unpack},
};
use serde::{Deserialize, Serialize};

pub use types::*;

#[derive(Serialize, Deserialize)]
pub struct Config {
    /// Its hash is used as port ID. Address (string) or script.
    pub user_lock_script: AddressOrScript,

    /// Axon metadata cell type script.
    pub axon_metadata_type_script: AddressOrScript,
    pub channel_contract_type_id_args: H256,
    pub channel_id: u16,

    pub packet_contract_type_id_args: H256,

    pub confirmations: u32,
}

impl Config {
    pub fn user_lock_script(&self) -> packed::Script {
        self.user_lock_script.script()
    }

    pub fn axon_metadata_type_script(&self) -> packed::Script {
        self.axon_metadata_type_script.script()
    }

    fn type_id_type_script(args: &H256) -> packed::Script {
        packed::Script::new_builder()
            .code_hash(TYPE_ID_CODE_HASH.pack())
            .hash_type(ScriptHashType::Type.into())
            .args(args.0[..].pack())
            .build()
    }

    pub fn channel_contract_type_script(&self) -> packed::Script {
        Self::type_id_type_script(&self.channel_contract_type_id_args)
    }

    pub fn channel_cell_lock_script(&self) -> packed::Script {
        let channel_args = ChannelArgs {
            client_id: self
                .axon_metadata_type_script()
                .calc_script_hash()
                .unpack()
                .0,
            open: true,
            channel_id: self.channel_id,
            port_id: self.user_lock_script().calc_script_hash().unpack().0,
        };
        packed::Script::new_builder()
            .hash_type(ScriptHashType::Type.into())
            .code_hash(self.channel_contract_type_script().calc_script_hash())
            .args(channel_args.to_args().pack())
            .build()
    }

    pub fn packet_contract_type_script(&self) -> packed::Script {
        Self::type_id_type_script(&self.packet_contract_type_id_args)
    }

    pub fn packet_cell_lock_script_prefix(&self) -> packed::Script {
        let packet_args = PacketArgs {
            channel_id: self.channel_id,
            port_id: self.user_lock_script().calc_script_hash().unpack().0,
            sequence: 0,
        };

        packed::Script::new_builder()
            .hash_type(ScriptHashType::Type.into())
            .code_hash(self.packet_contract_type_script().calc_script_hash())
            .args(packet_args.get_search_args(true).pack())
            .build()
    }

    /// Packet cell lock script for certain sequence number.
    pub fn packet_cell_lock_script(&self, sequence: u16) -> packed::Script {
        let packet_args = PacketArgs {
            channel_id: self.channel_id,
            port_id: self.user_lock_script().calc_script_hash().unpack().0,
            sequence,
        };

        packed::Script::new_builder()
            .hash_type(ScriptHashType::Type.into())
            .code_hash(self.packet_contract_type_script().calc_script_hash())
            .args(packet_args.to_args().pack())
            .build()
    }
}
