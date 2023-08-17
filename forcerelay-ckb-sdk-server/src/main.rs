use std::{net::SocketAddr, sync::Arc};

use clap::Parser;
use forcerelay_ckb_sdk_server::*;
use jsonrpc_utils::{
    jsonrpc_core::{Compatibility, MetaIoHandler},
    stream::StreamServerConfig,
};

#[derive(Parser)]
struct Args {
    #[clap(long)]
    ckb_rpc: String,
    #[clap(long)]
    bind: SocketAddr,
}

#[tokio::main]
async fn main() -> Result<(), hyper::Error> {
    let args = Args::parse();

    let rpc_impl = RpcImpl::new(args.ckb_rpc);

    let mut handler = MetaIoHandler::with_compatibility(Compatibility::V2);
    add_rpc_methods(&mut handler, rpc_impl);

    let server = jsonrpc_utils::axum_utils::jsonrpc_router(
        "/",
        Arc::new(handler),
        StreamServerConfig::default().with_keep_alive(true),
    );

    axum::Server::try_bind(&args.bind)?
        .serve(server.into_make_service())
        .await
}
