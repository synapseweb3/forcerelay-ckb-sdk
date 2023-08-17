use anyhow::Result;
use ckb_fixed_hash::H256;
use ckb_jsonrpc_types::{JsonBytes, TransactionView, Uint32};
use ckb_sdk::rpc::ckb_indexer::{Cell, Order, Pagination, SearchKey, Tip};
use jsonrpc_utils::{rpc_client, HttpClient};
use serde::{Deserialize, Serialize};

/// Async CKB RPC client. The indexer module is assumed to be enabled.
#[derive(Clone)]
pub struct CkbRpcClient {
    inner: HttpClient,
}

impl CkbRpcClient {
    pub fn new(url: String) -> Self {
        Self {
            inner: HttpClient::new(url),
        }
    }
}

#[rpc_client]
impl CkbRpcClient {
    pub async fn get_transaction(&self, tx_hash: H256) -> Result<MyTransactionWithStatusResponse>;
    pub async fn get_indexer_tip(&self) -> Result<Option<Tip>>;
    pub async fn get_cells(
        &self,
        search_key: SearchKey,
        order: Order,
        limit: Uint32,
        after: Option<JsonBytes>,
    ) -> Result<Pagination<Cell>>;
}

/// Like TransactionWithStatusResponse but only json.
#[derive(Serialize, Deserialize)]
pub struct MyTransactionWithStatusResponse {
    pub transaction: Option<TransactionView>,
}
