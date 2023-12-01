use ckb_ics_axon::message::MsgType;
use forcerelay_ckb_sdk::json::JsonEnvelope;

#[test]
fn test_envelope_serde() {
    let e = JsonEnvelope {
        content: [3, 4].to_vec(),
        commitments: Vec::new(),
        msg_type: MsgType::MsgAckPacket,
    };
    let json = serde_json::to_string(&e).unwrap();
    assert_eq!(
        json,
        r#"{"msg_type":"MsgAckPacket","content":"0x0304","commitments":[]}"#
    );
    let e1: JsonEnvelope = serde_json::from_str(&json).unwrap();
    assert_eq!(e1, e);
}
