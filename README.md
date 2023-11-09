# Forcerelay CKB SDK

Forcerelay-ckb-sdk is a rust library that can be used for building programs to
interact with ckb ibc modules in forcerelay cross-chain applications.

## Example - sudt-transfer

The [sudt-transfer](examples/sudt-transfer.rs) example demonstrates how to use
forcerelay-ckb-sdk to build a cli for cross-chain SUDT transfer with the [sudt-transfer](https://github.com/synapseweb3/forcerelay-ckb-contracts/tree/master/contracts/ibc-app/sudt-transfer) module.

## APIs

When you want to send a packet, use `assemble_send_packet_partial_transaction`
to build a transaction, add any inputs/outputs/deps/witnesses required by the module,
add the ibc envelope witness, balance, sign and send it.

(Balancing and signing these transactions can be a bit tricky because the envelope witness need to be the last witness. See how it can be implemented with ckb-sdk in the `complete_tx` function in the sudt-transfer example.)

After the packet is processed by the counterparty module, the relayer will
create an ack packet cell. You should subscribe to such cells and consume them
with `assemble_consume_ack_packet_partial_transaction`.

When you need to receive a packet, use `assemble_write_ack_partial_transaction`.

The cell deps and channel cells needed for these functions can be found with the
`search` module.

Use `cargo +nightly doc --open` to view the full API docs.

## Configuration

- module_lock_script
- axon_metadata_type_script
- channel_contract_type_id_args
- channel_id
- packet_contract_type_id_args
- confirmations

## JSONRPC

There's a `forcerelay-ckb-sdk-server` that wraps the API functions as JSONRPC methods if you want to build cross-chain applications in languages other than rust.
