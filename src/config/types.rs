use std::{fmt, str::FromStr};

use ckb_jsonrpc_types::Script;
use ckb_sdk::Address;
use ckb_types::packed;
use serde::{de::Visitor, Deserialize, Deserializer, Serialize, Serializer};

#[derive(Serialize, Deserialize)]
#[serde(untagged)]
pub enum AddressOrScript {
    Script(Script),
    Address(AddressString),
}

impl AddressOrScript {
    pub fn script(&self) -> packed::Script {
        match self {
            Self::Script(s) => s.clone().into(),
            Self::Address(a) => (&a.0).into(),
        }
    }
}

pub struct AddressString(pub Address);

struct AddressStringVisitor;

impl<'de> Visitor<'de> for AddressStringVisitor {
    type Value = AddressString;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a CKB address")
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        let a = Address::from_str(v).map_err(serde::de::Error::custom)?;
        Ok(AddressString(a))
    }

    fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        let a = Address::from_str(&v).map_err(serde::de::Error::custom)?;
        Ok(AddressString(a))
    }
}

impl<'de> Deserialize<'de> for AddressString {
    fn deserialize<D>(deserializer: D) -> Result<AddressString, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(AddressStringVisitor)
    }
}

impl Serialize for AddressString {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0.to_string())
    }
}
