#![allow(dead_code)]
use csgn::{Kind as CoseKind, SecretKey, Signer};
use csrn::cchr::AuthenticatedOrigin;
use serde_json::{Value, json};

pub const NOW: u64 = 1_800_000_000;
pub const ORIGIN: &str = "https://alpha.example.test";

pub fn signer() -> Signer {
    Signer::new("alpha", SecretKey::from_seed(&mut [71; 32]), NOW - 1, 1000).unwrap()
}
pub fn sign(s: &mut Signer, kind: CoseKind, payload: Value) -> Vec<u8> {
    s.sign(kind, &serde_json::to_vec(&payload).unwrap(), NOW, NOW + 500)
        .unwrap()
}
pub fn feed(s: &mut Signer, revision: u64, epoch: u64) -> Value {
    let schema = json!({"community":"alpha","version":1,"public":[],"private":[]});
    let manifest = json!({"purpose":"cplc.trust.v1","community":"alpha","revision":revision,
        "policy_epoch":epoch,"key_ring":s.key_ring().to_cbor(),"schema_version":1});
    let mut v = json!({"revision":revision,"policy_epoch":epoch,"key_ring":s.key_ring().to_cbor(),
        "manifest":sign(s,CoseKind::SettingsSnapshot,manifest)});
    for (name, kind, content) in [
        (
            "settings",
            CoseKind::SettingsSnapshot,
            json!({"action.admission":{"all_of":[],"any_of":[{"gate":"voucher"}],"k_of_n":{"k":1,"of":[{"gate":"voucher"}]}}}),
        ),
        ("schema", CoseKind::SchemaSnapshot, schema.clone()),
        (
            "schema_versions",
            CoseKind::SchemaSnapshot,
            json!({"purpose":"cplc.schema-versions.v1","current":1,"versions":[{"schema":schema,"changes":null}]}),
        ),
        (
            "communities",
            CoseKind::CommunitiesSnapshot,
            json!(["alpha"]),
        ),
        (
            "revocations",
            CoseKind::RevocationListSnapshot,
            json!({"members":["revoked"],"devices":vec![[22u8;32]]}),
        ),
    ] {
        v[name] = json!(sign(
            s,
            kind,
            json!({"community":"alpha","revision":revision,"policy_epoch":epoch,"content":content})
        ));
    }
    v
}
pub fn authority(s: &Signer) -> AuthenticatedOrigin {
    AuthenticatedOrigin::from_authenticated_response(
        ORIGIN,
        "alpha",
        &s.key_ring().to_cbor(),
        1,
        NOW,
        NOW + 100,
    )
    .unwrap()
}
pub fn bytes(v: &Value) -> Vec<u8> {
    serde_json::to_vec(v).unwrap()
}
pub fn replace(
    s: &mut Signer,
    v: &mut Value,
    name: &str,
    kind: CoseKind,
    edit: impl FnOnce(&mut Value),
) {
    let cose: Vec<u8> = serde_json::from_value(v[name].clone()).unwrap();
    let verified = s.key_ring().verify(&cose, kind, NOW).unwrap();
    let mut payload: Value = serde_json::from_slice(verified.payload()).unwrap();
    edit(&mut payload);
    v[name] = json!(sign(s, kind, payload));
}
