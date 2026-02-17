//! Support for Hybrid Compute offchain operations

/*
  HC Error Codes
  ERR_NONE     = 0 Success
  ERR_REMOTE   = 1 Offchain server provided an error response; its delivery was successful
  ERR_RPC      = 2 JSON-RPC returned an error result; message is copied
  ERR_DECODE   = 3 JSON-RPC response was not valid
  ERR_OTHER    = 4 Internal error or unexpected RPC error
  ERR_PAYMENT  = 5 Calling contract did not provide sufficient payment
  ERR_CONNECT  = 6 Unable to connect to RPC server (incl. 500-class HTTP error). Considered to be a temporary failure.
*/

use std::{
    collections::HashMap,
    str::FromStr,
    sync::Mutex,
    time::{Duration, SystemTime},
};

//use alloy_sol_types::SolType;
use alloy_primitives::map::FbBuildHasher;
use alloy_primitives::{Address, B256, Bytes, Signature, U256, keccak256};
use alloy_rpc_types_eth::state::{AccountOverride, StateOverride};
use alloy_signer::{/* Signature / *, SignerSync,*/ Signer};
use alloy_signer_local::{LocalSigner, PrivateKeySigner};
use alloy_sol_types::{/*SolCall, SolStruct,*/ SolValue};
use once_cell::sync::Lazy;

use crate::{
    EntryPointVersion,
    chain::ChainSpec,
    user_operation::{
        UserOperation, UserOperationOptionalGas,
        v0_6::UserOperationOptionalGas as UserOperationOptionalGasV0_6,
        v0_7::UserOperationOptionalGas as UserOperationOptionalGasV0_7,
    },
};

#[derive(Clone, Debug)]
/// Error code
pub struct HcErr {
    /// numeric code
    pub code: u32,
    /// message
    pub message: String,
}

#[derive(Debug)]
/// Cache entry containing an offchain operation
pub struct HcEntry {
    /// Partial key, to be combined with msg.sender in the Helper contract
    pub sub_key: B256,
    /// Merged key, used for end-of-bundle cleanup
    pub map_key: B256,
    /// Extracted calldata (also in user_op; duplicated for easier access)
    pub call_data: Bytes,
    /// Full operation
    pub user_op: UserOperationOptionalGas,
    /// Creation timestamp, used to prune expired entries
    pub ts: SystemTime,
    /// The total computed offchain gas (all 3 phases)
    pub oc_gas: u128,
    /// The required preVerificationGas incl. HC overhead (set during successful gas estimation)
    pub needed_pvg: u128,
    /// Version flag
    pub is_v7: bool,
    /// Workaround to check for stale cache entries
    pub valid: bool,
}

/// Duration after which a cache entry is removed
const EXPIRE_SECS: std::time::Duration = Duration::new(180, 0);
/// Duration after which a cache entry is treated as stale (rejecting a userOp)
const STALE_SECS: std::time::Duration = Duration::new(120, 0);

/// Selector for "_register(address,string)"
pub const REG_SELECTOR: &str = "aca1d472";

impl Clone for HcEntry {
    fn clone(&self) -> HcEntry {
        HcEntry {
            sub_key: self.sub_key,
            map_key: self.map_key,
            call_data: self.call_data.clone(),
            user_op: self.user_op.clone(),
            ts: self.ts,
            oc_gas: self.oc_gas,
            needed_pvg: self.needed_pvg,
            is_v7: self.is_v7,
            valid: self.valid,
        }
    }
}

static HC_MAP: Lazy<Mutex<HashMap<B256, HcEntry>>> = Lazy::new(|| {
    let m = HashMap::new();
    Mutex::new(m)
});

#[derive(Clone, Debug)]
/// Parameters needed for Hybrid Compute, accessed from various modules.
pub struct HcCfg {
    /// Helper contract address
    pub helper_addr: Address,
    /// HybridAccount used to insert error msgs
    pub sys_account: Address,
    /// Owner/signer for sys_account
    pub sys_owner: Address,
    /// Private key for sys_account
    pub sys_privkey: B256,
    /// Chain spec
    pub chain_spec: ChainSpec,
    /// Temporary workaround; would be better to use an existing Provider.
    pub node_http: String,
    /// Temporary workaround
    pub from_addr: Address,
    /// Index of ResponseCache slot in HCHelper
    pub slot_idx: U256,
}

//pub static mut HC_CONFIG: HcCfg = HcCfg { helper_addr:Address::zero(), sys_account:Address::zero(),  sys_owner:Address::zero(), sys_privkey:B256::zero(), entry_point: Address::zero(), chain_id: 0, node_http:String::new(), from_addr: Address::zero()};

/// Parameters needed for Hybrid Compute, accessed from various modules.
pub static HC_CONFIG: Lazy<Mutex<HcCfg>> = Lazy::new(|| {
    let c = HcCfg {
        helper_addr: Address::ZERO,
        sys_account: Address::ZERO,
        sys_owner: Address::ZERO,
        sys_privkey: B256::ZERO,
        chain_spec: ChainSpec::default(),
        node_http: String::new(),
        from_addr: Address::ZERO,
        slot_idx: U256::from(0),
    };
    Mutex::new(c)
});

/// Set the HC parameters based on CLI args
pub fn init(
    helper_addr: Address,
    sys_account: Address,
    sys_owner: Address,
    sys_privkey: B256,
    chain_spec: ChainSpec,
    node_http: String,
    slot_idx: U256,
) {
    let mut cfg = HC_CONFIG.lock().unwrap();

    cfg.helper_addr = helper_addr;
    cfg.sys_account = sys_account;
    cfg.sys_owner = sys_owner;
    cfg.sys_privkey = sys_privkey;
    cfg.chain_spec = chain_spec;
    cfg.node_http.clone_from(&node_http);
    cfg.slot_idx = slot_idx;
}

/// Extract the sender field of a cached entry
pub fn get_hc_sender(ent: HcEntry) -> Address {
    let op7 = ent
        .user_op
        .into_variant(&HC_CONFIG.lock().unwrap().chain_spec);
    op7.sender()
}

/// Set the EOA address which the bundler is using. Erigon, but not geth, needs this for tx simulation
/// Boba is deprecating Erigon so this will be removed
pub fn set_signer(from_addr: Address) {
    let mut cfg = HC_CONFIG.lock().unwrap();
    cfg.from_addr = from_addr;
}

/// Wrap the response payload into calldata for the HybridAccount + HCHelper contracts
pub fn make_op_calldata(sender: Address, map_key: B256, payload: Bytes) -> Bytes {
    let mut put_data = [0xdfu8, 0xc9, 0x8a, 0xe8].to_vec(); // helper "PutResponse(bytes32,bytes)" selector

    let p1_enc = Bytes((map_key, payload).abi_encode().into()).slice(32..);
    put_data.extend(p1_enc);

    let mut tmp_data = [0xb6u8, 0x1d, 0x27, 0xf6].to_vec(); // account "execute" selector
    let p2_bytes = Bytes((sender, U256::ZERO, put_data).abi_encode().into()).slice(32..);
    tmp_data.extend(&p2_bytes);

    tmp_data.into()
}

/// Wrap the error response payload into calldata for the HybridAccount + HCHelper contracts
pub fn make_err_calldata(sender: Address, map_key: B256, payload: Bytes) -> Bytes {
    let mut put_data = [0xfdu8, 0xe8, 0x9b, 0x64].to_vec(); // helper "PutSysResponse(bytes32,bytes)" selector

    let p1_enc = Bytes((map_key, payload).abi_encode().into()).slice(32..);
    put_data.extend(p1_enc);

    let mut tmp_data = [0xb6u8, 0x1d, 0x27, 0xf6].to_vec(); // account "execute" selector
    let p2_bytes = Bytes((sender, U256::ZERO, put_data).abi_encode().into()).slice(32..);
    tmp_data.extend(p2_bytes);

    tmp_data.into()
}

/// Cleanup to remove any leaked responses at the end of a bundle
pub fn make_rr_calldata(keys: Vec<B256>) -> Bytes {
    let mut put_data = [0x10u8, 0x40, 0x4d, 0x34].to_vec(); // helper RemoveResponses(bytes32[])
    let cfg = HC_CONFIG.lock().unwrap();

    let k_bytes = Bytes(keys.abi_encode().into()); // note - prefix is not removed from this abi.encode()
    put_data.extend(k_bytes);

    let mut tmp_data = [0xb6u8, 0x1d, 0x27, 0xf6].to_vec(); // account "execute" selector
    let p2_bytes = Bytes((cfg.helper_addr, U256::ZERO, put_data).abi_encode().into()).slice(32..);
    tmp_data.extend(p2_bytes);

    tmp_data.into()
}

/// Check for a trigger string in the revert data
pub fn check_trigger(rev: &Bytes) -> bool {
    const MIN_REQ_LEN: usize = 8 + 20 + 32 + 4; // trigger prefix + endpoint_addr + user_key + 4-byte selector

    const TRIGGER: [u8; 8] = [0x5f, 0x48, 0x43, 0x5f, 0x54, 0x52, 0x49, 0x47];

    if rev.len() >= MIN_REQ_LEN {
        let trigger_status = rev[0..8] == TRIGGER;
        //println!("HC trigger status {:?} for {:?}", trigger_status, rev);
        return trigger_status;
    }
    false
}

/// Key used to store response in the HCHelper mapping
pub fn hc_map_key(revert_data: &Bytes) -> B256 {
    let sub_key: B256 = keccak256(&revert_data[28..]);
    let map_key: B256 = keccak256([&revert_data[8..28], sub_key.as_slice()].concat());
    map_key
}

/// Calculates the HCHelper storage slot key for a ResponseCache entry
pub fn hc_storage_key(map_key: B256) -> B256 {
    let cfg = HC_CONFIG.lock().unwrap();
    let slot_idx_bytes: Bytes = cfg.slot_idx.abi_encode().into();

    let mut tmp = map_key.to_vec();
    tmp.extend(slot_idx_bytes);
    let storage_key: B256 = keccak256(tmp); // [Bytes::from(map_key.to_fixed_bytes()), slot_idx_bytes].concat()).into();
    storage_key
}

/// Partial key, to be combined with msg.sender
pub fn hc_sub_key(revert_data: &Bytes) -> B256 {
    let sub_key: B256 = keccak256(&revert_data[28..]);
    sub_key
}

/// Endpoint address (address of HybridAccount which called HCHelper)
pub fn hc_ha_addr(revert_data: &Bytes) -> Address {
    Address::from_slice(&revert_data[8..28])
}

/// Extract the function selector called by the HC operation
pub fn hc_selector(revert_data: &Bytes) -> [u8; 4] {
    let sel_bytes: [u8; 4] = revert_data[60..64].to_vec().try_into().unwrap();
    sel_bytes
}

/// Extract the request payload
pub fn hc_req_payload(revert_data: &Bytes) -> Vec<u8> {
    revert_data[64..].to_vec()
}

/// Internal function to generate a UserOperation for an offchain response
#[allow(clippy::too_many_arguments)] // FIXME later
fn make_external_op(
    src_addr: Address,
    nonce: U256,
    op_success: bool,
    response_payload: &Bytes,
    sub_key: B256,
    ha_addr: Address,
    sig_hex: String,
    oo_nonce: U256,
    cfg: &HcCfg,
) -> (UserOperationOptionalGas, Bytes) {
    let tmp_bytes: Bytes = Bytes::from(response_payload.to_vec());

    let err_code: u32 = if op_success { 0 } else { 1 };

    let enc_merged_response =
        Bytes((src_addr, nonce, err_code, tmp_bytes).abi_encode().into()).slice(32..);

    let call_data = make_op_calldata(cfg.helper_addr, sub_key, enc_merged_response);

    let call_gas = 705 * response_payload.len() + 170000;

    //println!(
    //    "HC external_op call_data len {:?} {:?} gas {:?} {:?}",
    //    response_payload.len(),
    //    call_data.len(),
    //    call_gas,
    //    call_data
    //);
    if true {
        let mut new_op = UserOperationOptionalGasV0_7 {
            sender: ha_addr,
            nonce: oo_nonce,
            call_data: call_data.clone(),
            call_gas_limit: Some(call_gas.try_into().unwrap()),
            verification_gas_limit: Some(0x10000),
            pre_verification_gas: Some(0x10000),
            max_fee_per_gas: Some(0),
            max_priority_fee_per_gas: Some(0),
            paymaster_data: Bytes::new(),
            signature: Bytes::new(),
            entry_point_version: EntryPointVersion::V0_7,
            paymaster: None,
            factory: None,
            factory_data: Bytes::new(),
            paymaster_verification_gas_limit: None,
            paymaster_post_op_gas_limit: None,
            paymaster_signature: None,
            eip7702_auth_address: None,
            aggregator: None,
        };

        new_op.signature = sig_hex.parse::<Bytes>().unwrap();
        (UserOperationOptionalGas::V0_7(new_op), call_data)
    } else {
        let mut new_op = UserOperationOptionalGasV0_6 {
            sender: ha_addr,
            nonce: oo_nonce,
            init_code: Bytes::new(),
            call_data: call_data.clone(),
            call_gas_limit: Some(call_gas.try_into().unwrap()),
            verification_gas_limit: Some(0x10000),
            pre_verification_gas: Some(0x10000),
            max_fee_per_gas: Some(0),
            max_priority_fee_per_gas: Some(0),
            paymaster_and_data: Bytes::new(),
            signature: Bytes::new(),
            eip7702_auth_address: None,
            aggregator: None,
        };

        new_op.signature = sig_hex.parse::<Bytes>().unwrap();

        (UserOperationOptionalGas::V0_6(new_op), call_data)
    }
}

/// Processes an external hybrid compute op.
#[allow(clippy::too_many_arguments)] // FIXME later
pub async fn external_op(
    entry_point: Address,
    op_key: B256,
    src_addr: Address,
    nonce: U256,
    op_success: bool,
    response_payload: &Bytes,
    sub_key: B256,
    ha_addr: Address,
    sig_hex: String,
    oo_nonce: U256,
    map_key: B256,
    cfg: &HcCfg,
    ha_owner: Address,
    nn: U256,
) -> HcErr {
    let (mut new_op, mut new_cd) = make_external_op(
        src_addr,
        nonce,
        op_success,
        response_payload,
        sub_key,
        ha_addr,
        sig_hex.clone(),
        oo_nonce,
        cfg,
    );

    let check_hash = new_op
        .into_variant(&cfg.chain_spec)
        .hash(/*entry_point, cfg.chain_spec.id*/);
    let check_sig: Signature = Signature::from_str(&sig_hex).expect("Signature decode");
    let check_msg = check_hash.to_vec(); // check_hash.to_fixed_bytes().to_vec();

    let mut hc_err = HcErr {
        code: 0,
        message: "".to_string(),
    };

    let s2: Signature = check_sig;

    // let sig_bytes = Bytes::from_str(&sig_hex)
    // let test_sig = PrimitiveSignature::decode_rlp_vrs(
    let test2 = s2
        .recover_address_from_msg(check_msg)
        .expect("Recover signature");

    //    if check_sig.verify(check_msg, ha_owner).is_err() {
    if test2 != ha_owner {
        println!("HC Bad offchain signature");
        hc_err = HcErr {
            code: 3,
            message: "HC03: Bad offchain signature".to_string(),
        };
        let key_bytes: B256 = cfg.sys_privkey;
        let wallet = LocalSigner::from_bytes(&key_bytes).unwrap();

        (new_op, new_cd) = make_err_op(
            hc_err.clone(),
            sub_key,
            src_addr,
            nn,
            oo_nonce,
            cfg,
            entry_point,
            wallet,
        )
        .await;
    }

    let ent: HcEntry = HcEntry {
        sub_key,
        map_key,
        call_data: new_cd.clone(),
        user_op: new_op.clone(),
        ts: SystemTime::now(),
        oc_gas: 0,
        needed_pvg: 0,
        is_v7: true,
        valid: true,
    };
    HC_MAP.lock().unwrap().insert(op_key, ent);

    hc_err
}

#[allow(clippy::too_many_arguments)] // FIXME later
async fn make_err_op(
    err_hc: HcErr,
    sub_key: B256,
    src_addr: Address,
    nn: U256,
    oo_nonce: U256,
    cfg: &HcCfg,
    _entry_point: Address,
    wallet: PrivateKeySigner,
) -> (UserOperationOptionalGas, Bytes) {
    //    let response_payload: Bytes =
    //        AbiEncode::encode((src_addr, nn, err_hc.code, err_hc.message)).into();

    //let response_call = PutResponseCall { src_addr: src_addr, nn: nn.into(), errCode: err_hc.code, msgBytes: err_hc.message.into() };
    //let response_struct = InnerResponse {a1: src_addr, b1: nn, c1: err_hc.code.into(), d1: err_hc.message.into() };
    let err_num = U256::from(err_hc.code); // actually U32
    let err_str: String = err_hc.message;

    let response_payload = Bytes((src_addr, nn, err_num, err_str).abi_encode().into()).slice(32..);

    let call_data = make_err_calldata(
        cfg.helper_addr,
        sub_key,
        Bytes::from(response_payload.to_vec()),
    );

    if true {
        let mut new_op = UserOperationOptionalGasV0_7 {
            sender: cfg.sys_account,
            nonce: oo_nonce,
            call_data: call_data.clone(),
            call_gas_limit: Some(0x40000),
            verification_gas_limit: Some(0x10000),
            pre_verification_gas: Some(0x10000),
            max_fee_per_gas: Some(0),
            max_priority_fee_per_gas: Some(0),
            paymaster_data: Bytes::new(),
            signature: Bytes::new(),
            entry_point_version: EntryPointVersion::V0_7,
            paymaster: None,
            factory: None,
            factory_data: Bytes::new(),
            paymaster_verification_gas_limit: None,
            paymaster_post_op_gas_limit: None,
            paymaster_signature: None,
            eip7702_auth_address: None,
            aggregator: None,
        };
        let hh = UserOperationOptionalGas::V0_7(new_op.clone())
            .into_variant(&cfg.chain_spec)
            .hash(/*entry_point, cfg.chain_spec.id*/);
        let signature = wallet.sign_message(hh.as_slice()).await.unwrap();
        let sig_bytes: Bytes = signature.as_bytes().into();
        println!("HC err_op signed {:?} {:?}", signature, sig_bytes);
        new_op.signature = sig_bytes;

        (UserOperationOptionalGas::V0_7(new_op), call_data)
    } else {
        let mut new_op = UserOperationOptionalGasV0_6 {
            sender: cfg.sys_account,
            nonce: oo_nonce,
            init_code: Bytes::new(),
            call_data: call_data.clone(),
            call_gas_limit: Some(0x40000),
            verification_gas_limit: Some(0x10000),
            pre_verification_gas: Some(0x10000),
            max_fee_per_gas: Some(0),
            max_priority_fee_per_gas: Some(0),
            paymaster_and_data: Bytes::new(),
            signature: Bytes::new(),
            eip7702_auth_address: None,
            aggregator: None,
        };
        let hh = UserOperationOptionalGas::V0_6(new_op.clone())
            .into_variant(&cfg.chain_spec)
            .hash(/*entry_point, cfg.chain_spec.id*/);
        let signature = wallet.sign_message(hh.as_slice()).await.unwrap();
        let sig_bytes: Bytes = signature.as_bytes().into();
        println!("HC err_op signed {:?} {:?}", signature, sig_bytes);
        new_op.signature = sig_bytes;

        (UserOperationOptionalGas::V0_6(new_op), call_data)
    }
}

/// Encapsulate an error code into a UserOperation
#[allow(clippy::too_many_arguments)] // FIXME later
pub async fn err_op(
    op_key: B256,
    entry_point: Address,
    err_hc: HcErr,
    sub_key: B256,
    src_addr: Address,
    nn: U256,
    oo_nonce: U256,
    map_key: B256,
    cfg: &HcCfg,
) {
    println!(
        "HC hybrid_compute err_op op_key {:?} err_str {:?}",
        op_key, err_hc.message
    );
    assert!(err_hc.code >= 2);
    let key_bytes: B256 = cfg.sys_privkey;
    let wallet = LocalSigner::from_bytes(&key_bytes).unwrap();

    let (new_op, new_cd) = make_err_op(
        err_hc,
        sub_key,
        src_addr,
        nn,
        oo_nonce,
        cfg,
        entry_point,
        wallet,
    )
    .await;

    let ent: HcEntry = HcEntry {
        sub_key,
        map_key,
        call_data: new_cd.clone(),
        user_op: new_op.clone(),
        ts: SystemTime::now(),
        oc_gas: 0,
        needed_pvg: 0,
        is_v7: true,
        valid: true,
    };
    HC_MAP.lock().unwrap().insert(op_key, ent);
}

/// Encapsulate a RemoveResponses into a UserOperation
pub async fn rr_op(
    cfg: &HcCfg,
    _entry_point: Address,
    oo_nonce: U256,
    keys: Vec<B256>,
) -> UserOperationOptionalGas {
    let call_data = make_rr_calldata(keys);
    //println!("HC rr_op call_data {:?}", call_data);

    if true {
        let mut new_op = UserOperationOptionalGasV0_7 {
            sender: cfg.sys_account,
            nonce: oo_nonce,
            call_data: call_data.clone(),
            call_gas_limit: Some(0x6000),
            verification_gas_limit: Some(0x10000),
            pre_verification_gas: Some(0x10000),
            max_fee_per_gas: Some(0),
            max_priority_fee_per_gas: Some(0),
            paymaster_data: Bytes::new(),
            signature: Bytes::new(),
            entry_point_version: EntryPointVersion::V0_7,
            paymaster: None,
            factory: None,
            factory_data: Bytes::new(),
            paymaster_verification_gas_limit: None,
            paymaster_post_op_gas_limit: None,
            paymaster_signature: None,
            eip7702_auth_address: None,
            aggregator: None,
        };

        let key_bytes: B256 = cfg.sys_privkey;
        let wallet = LocalSigner::from_bytes(&key_bytes).unwrap();

        let hh = UserOperationOptionalGas::V0_7(new_op.clone())
            .into_variant(&cfg.chain_spec)
            .hash(/*entry_point, cfg.chain_spec.id*/);

        let signature = wallet.sign_message(hh.as_slice()).await.unwrap();
        new_op.signature = signature.as_bytes().into();
        //println!("HC rr_op signed {:?} {:?}", signature, new_op.signature);

        UserOperationOptionalGas::V0_7(new_op)
    } else {
        let mut new_op = UserOperationOptionalGasV0_6 {
            sender: cfg.sys_account,
            nonce: oo_nonce,
            init_code: Bytes::new(),
            call_data: call_data.clone(),
            call_gas_limit: Some(0x6000),
            verification_gas_limit: Some(0x10000),
            pre_verification_gas: Some(0x10000),
            max_fee_per_gas: Some(0), // Some(U256::zero()),
            max_priority_fee_per_gas: Some(0),
            paymaster_and_data: Bytes::new(),
            signature: Bytes::new(),
            eip7702_auth_address: None,
            aggregator: None,
        };

        let key_bytes: B256 = cfg.sys_privkey;
        let wallet = LocalSigner::from_bytes(&key_bytes).unwrap();

        let hh = UserOperationOptionalGas::V0_6(new_op.clone())
            .into_variant(&cfg.chain_spec)
            .hash(/*entry_point, cfg.chain_spec.id*/);
        println!("HC pre_sign hash {:?}", hh);

        let signature = wallet.sign_message(hh.as_slice()).await.unwrap();
        new_op.signature = signature.as_bytes().into();
        //println!("HC rr_op signed {:?} {:?}", signature, new_op.signature);

        UserOperationOptionalGas::V0_6(new_op)
    }
}

/// Retrieve a cached HC operation, checking for staleness
pub fn get_hc_ent(key: B256) -> Option<HcEntry> {
    if let Some(mut hc_ent) = HC_MAP.lock().unwrap().get(&key).cloned() {
        let stale_time = SystemTime::now().checked_sub(STALE_SECS).unwrap();
        let ent_time = hc_ent.ts;
        hc_ent.valid = ent_time > stale_time;
        return Some(hc_ent);
    }
    None
}

/// Remove a cache entry
pub fn del_hc_ent(key: B256) {
    HC_MAP.lock().unwrap().remove(&key);
}

/// Retrieve the PutResponse() payload from a cached HC operation
pub fn get_hc_op_payload(key: B256) -> Bytes {
    let op = HC_MAP.lock().unwrap().get(&key).cloned().unwrap();
    let cd1 = &op.call_data[4..];

    let ddd = <(Address, B256, Bytes)>::abi_decode_sequence(cd1).unwrap();
    let db2: Bytes = ddd.2;

    let dec2 = <(B256, Bytes)>::abi_decode_sequence(&db2.slice(4..)).unwrap();
    dec2.1
}

/// Retrieve the map_key for a cached op
pub fn get_hc_map_key(key: B256) -> B256 {
    HC_MAP.lock().unwrap().get(&key).cloned().unwrap().map_key
}

/// Retrieve a stateDiff object containing the encoded payload
pub fn get_hc_op_statediff(op_hash: B256, mut s2: StateOverride) -> StateOverride {
    if HC_MAP.lock().unwrap().get(&op_hash).is_none() {
        return s2;
    }
    let map_key = get_hc_map_key(op_hash);
    let mut key = hc_storage_key(map_key);

    let payload = get_hc_op_payload(op_hash);
    let cfg = HC_CONFIG.lock().unwrap();

    // Store an encoded length for the response bytes
    //let val = B256::from_low_u64_be((payload.len() * 2 + 1).try_into().unwrap());
    let val64: u64 = (payload.len() * 2 + 1).try_into().unwrap();
    let val: B256 = U256::from(val64).into();

    let s = FbBuildHasher::<32>::default();

    let mut hm = HashMap::with_hasher(s);
    //s2.account(cfg.helper_addr).store(key, val);
    hm.insert(key, val);

    key = keccak256(key);

    let mut i = 0;
    while i < payload.len() {
        let next_chunk: B256 = B256::from_slice(&payload[i..32 + i]);
        //s2.account(cfg.helper_addr).store(key, next_chunk);
        hm.insert(key, next_chunk);
        let u_key: U256 = key.into();
        key = B256::from(u_key.wrapping_add(U256::from(1)));
        i += 32;
    }

    let ao = AccountOverride {
        state_diff: Some(hm),
        ..Default::default()
    };

    s2.insert(cfg.helper_addr, ao);
    s2
}

/// Updates the preVerificationGas after a successful simulation.
pub fn hc_set_pvg(key: B256, needed_pvg: u128, oc_gas: u128) {
    let mut map = HC_MAP.lock().unwrap();
    let ent = map.get(&key).unwrap();
    //assert!(ent.needed_pvg == 0); // This is now allowed as an error flag
    // FIXME - should be a better way to do this.
    let new_ent = HcEntry {
        sub_key: ent.sub_key,
        map_key: ent.map_key,
        call_data: ent.call_data.clone(),
        user_op: ent.user_op.clone(),
        ts: ent.ts,
        needed_pvg,
        oc_gas,
        is_v7: ent.is_v7,
        valid: ent.valid,
    };
    map.remove(&key);
    map.insert(key, new_ent);
}

/// Updates the preVerificationGas after a successful simulation.
pub fn hc_get_pvg(key: B256) -> Option<u128> {
    if let Some(ent) = HC_MAP.lock().unwrap().get(&key).cloned() {
        return Some(ent.needed_pvg);
    }
    None
}

/// Iterate and remove expired cache entries
pub fn expire_hc_cache() {
    let mut map = HC_MAP.lock().unwrap();
    let exp_time = SystemTime::now().checked_sub(EXPIRE_SECS).unwrap();
    map.retain(|_, ent| ent.ts > exp_time);
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_init() {
        init(
            "0x0000000000000000000000000000000000000001"
                .parse::<Address>()
                .unwrap(),
            "0x0000000000000000000000000000000000000002"
                .parse::<Address>()
                .unwrap(),
            "0x0000000000000000000000000000000000000003"
                .parse::<Address>()
                .unwrap(),
            "0x1111111111111111111111111111111111111111111111111111111111111111"
                .parse::<B256>()
                .unwrap(),
            ChainSpec::default(),
            "http://test.local/rpc".to_string(),
            U256::from(2),
        );
        set_signer(
            "0x0000000000000000000000000000000000000005"
                .parse::<Address>()
                .unwrap(),
        );

        let expected: HcCfg = HcCfg {
            helper_addr: "0x0000000000000000000000000000000000000001"
                .parse::<Address>()
                .unwrap(),
            sys_account: "0x0000000000000000000000000000000000000002"
                .parse::<Address>()
                .unwrap(),
            sys_owner: "0x0000000000000000000000000000000000000003"
                .parse::<Address>()
                .unwrap(),
            sys_privkey: "0x1111111111111111111111111111111111111111111111111111111111111111"
                .parse::<B256>()
                .unwrap(),
            chain_spec: ChainSpec::default(),
            node_http: "http://test.local/rpc".to_string(),
            from_addr: "0x0000000000000000000000000000000000000005"
                .parse::<Address>()
                .unwrap(),
            slot_idx: U256::from(2),
        };
        let cfg: HcCfg = HC_CONFIG.lock().unwrap().clone();
        // chain_spec doesn't support PartialEq
        assert_eq!(expected.helper_addr, cfg.helper_addr);
        assert_eq!(expected.sys_account, cfg.sys_account);
        assert_eq!(expected.sys_owner, cfg.sys_owner);
        assert_eq!(expected.sys_privkey, cfg.sys_privkey);
        assert_eq!(expected.chain_spec.id, cfg.chain_spec.id);
        assert_eq!(expected.node_http, cfg.node_http);
        assert_eq!(expected.from_addr, cfg.from_addr);
    }

    #[test]
    fn test_trigger() {
        let t_no =  "0x5f41415f545249479c6df0d4c9d8f527221b59c66ad5279c16a1dbc221e8f4e33617575840a20013d516f1be1937bb52bbd7d525d996fd557d3d597f97e0d7ba00000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000001".parse::<Bytes>().unwrap();
        let t_yes = "0x5f48435f545249479c6df0d4c9d8f527221b59c66ad5279c16a1dbc221e8f4e33617575840a20013d516f1be1937bb52bbd7d525d996fd557d3d597f97e0d7ba00000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000001".parse::<Bytes>().unwrap();
        let t_short = "0x5f48435f545249479c6df0d4c9d8f527221b59c66ad5279c16a1dbc221e8f4e33617575840a20013d516f1be1937bb52bbd7d525d996fd557d3d597f97e0d7".parse::<Bytes>().unwrap();
        assert!(!check_trigger(&t_no));
        assert!(check_trigger(&t_yes));
        assert!(!check_trigger(&t_short));
    }

    #[test]
    fn test_req_parse() {
        let rev_data = "0x5f48435f545249479c6df0d4c9d8f527221b59c66ad5279c16a1dbc221e8f4e33617575840a20013d516f1be1937bb52bbd7d525d996fd557d3d597f97e0d7ba00000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000001".parse::<Bytes>().unwrap();
        let e_map_key = "0xa12faae2eedc0b231c96ab3c88c0b7e1e5dbc6fd02c462e79751c1eff7484efb"
            .parse::<B256>()
            .unwrap();
        let e_sub_key = "0x16d7f606293dca5dbbe97735b2913e6dade6e3f216310b12148cb67a6fd86947"
            .parse::<B256>()
            .unwrap();
        let e_ha_addr = "0x9c6df0d4c9d8f527221b59c66ad5279c16a1dbc2"
            .parse::<Address>()
            .unwrap();
        let e_sel = [151, 224, 215, 186];
        let e_payload = "0x00000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000001".parse::<Bytes>().unwrap();

        let map_key = hc_map_key(&rev_data);
        assert_eq!(e_map_key, map_key);
        let sub_key = hc_sub_key(&rev_data);
        assert_eq!(e_sub_key, sub_key);
        let ha_addr = hc_ha_addr(&rev_data);
        assert_eq!(e_ha_addr, ha_addr);
        let sel = hc_selector(&rev_data);
        assert_eq!(e_sel, sel);
        let payload = hc_req_payload(&rev_data);
        assert_eq!(e_payload, payload);
    }

    #[test]
    fn test_op_gen_external() {
        let cfg: HcCfg = HC_CONFIG.lock().unwrap().clone();

        let payload = "0x0000000000000000000000000000000000000000000000000000000000000002"
            .parse::<Bytes>()
            .unwrap();
        let (op, _) = make_external_op(
            "0x1000000000000000000000000000000000000001".parse::<Address>().unwrap(),
            U256::from(100),
            true,
            &payload,
            "0x2222222222222222222222222222222222222222222222222222222222222222".parse::<B256>().unwrap(),
            "0x2000000000000000000000000000000000000002".parse::<Address>().unwrap(),
            "0xfffffffffffffffffffffffffffffff0000000000000000000000000000000007aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1c".to_string(),
            U256::from(222),
            &cfg,
        );

        let e_calldata = "0xb61d27f60000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000124dfc98ae82222222222222222222222222222222222222222222222222222222222222222000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000c000000000000000000000000010000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000064000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000".parse::<Bytes>().unwrap();
        let expected = UserOperationOptionalGasV0_7 {
            sender: "0x2000000000000000000000000000000000000002".parse::<Address>().unwrap(),
            nonce: U256::from(222),
            call_data: e_calldata,
            call_gas_limit: Some(192560),
            verification_gas_limit: Some(65536),
            pre_verification_gas: Some(65536),
            max_fee_per_gas: Some(0),
            max_priority_fee_per_gas: Some(0),
            paymaster_data: Bytes::new(),
            signature: "0xfffffffffffffffffffffffffffffff0000000000000000000000000000000007aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1c".parse::<Bytes>().unwrap(),
            entry_point_version: EntryPointVersion::V0_7,
            paymaster: None,
            factory: None,
            factory_data: Bytes::new(),
            paymaster_verification_gas_limit: None,
            paymaster_post_op_gas_limit: None,
            paymaster_signature: None,
            eip7702_auth_address: None,
            aggregator: None,
        };
        if let UserOperationOptionalGas::V0_7(op7) = op {
            assert_eq!(expected, op7);
        } else {
            panic!("Invalud UserOperation variant");
        }
    }

    #[tokio::test]
    async fn test_op_gen_error() {
        let cfg = HcCfg {
            helper_addr: "0x0000000000000000000000000000000000000001"
                .parse::<Address>()
                .unwrap(),
            sys_account: "0x0000000000000000000000000000000000000002"
                .parse::<Address>()
                .unwrap(),
            sys_owner: "0x0000000000000000000000000000000000000003"
                .parse::<Address>()
                .unwrap(),
            sys_privkey: "0x1111111111111111111111111111111111111111111111111111111111111111"
                .parse::<B256>()
                .unwrap(),
            chain_spec: ChainSpec::default(),
            node_http: "http://test.local/rpc".to_string(),
            from_addr: "0x0000000000000000000000000000000000000005"
                .parse::<Address>()
                .unwrap(),
            slot_idx: U256::from(0),
        };

        let wallet = LocalSigner::from_bytes(&cfg.sys_privkey).unwrap();
        let op_future = make_err_op(
            HcErr {
                code: 4,
                message: "unit test".to_string(),
            },
            "0x2222222222222222222222222222222222222222222222222222222222222222"
                .parse::<B256>()
                .unwrap(),
            "0x2000000000000000000000000000000000000002"
                .parse::<Address>()
                .unwrap(),
            U256::from(100),
            U256::from(222),
            &cfg,
            "0x0000000000000000000000000000000000000004"
                .parse::<Address>()
                .unwrap(),
            wallet,
        );

        let e_calldata = "0xb61d27f60000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000124fde89b642222222222222222222222222222222222222222222222222222222222222222000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000c000000000000000000000000020000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000064000000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000009756e69742074657374000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000".parse::<Bytes>().unwrap();
        let expected = UserOperationOptionalGasV0_7 {
            sender: "0x0000000000000000000000000000000000000002"
                .parse::<Address>()
                .unwrap(),
            nonce: U256::from(222),
            call_data: e_calldata,
            call_gas_limit: Some(262144),
            verification_gas_limit: Some(65536),
            pre_verification_gas: Some(65536),
            max_fee_per_gas: Some(0),
            max_priority_fee_per_gas: Some(0),
            paymaster_data: Bytes::new(),
            signature:"0xfe10d7b74cc08f195b44caa8ce3dbd084941c5b26231f456d54cd101efe4e1ea37793d70c6732bbea5f10e9214ea2596fd5dfaf3f7c162b0c4d41a5d5eca64af1b"
                .parse::<Bytes>()
                .unwrap(),
            entry_point_version: EntryPointVersion::V0_7,
            paymaster: None,
            factory: None,
            factory_data: Bytes::new(),
            paymaster_verification_gas_limit: None,
            paymaster_post_op_gas_limit: None,
            paymaster_signature: None,
            eip7702_auth_address: None,
            aggregator: None,
        };
        let (op, _) = op_future.await;
        if let UserOperationOptionalGas::V0_7(op7) = op {
            assert_eq!(expected, op7);
        } else {
            panic!("Invalud UserOperation variant");
        }
    }
}
