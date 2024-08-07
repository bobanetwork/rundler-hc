// This file is part of Rundler.
//
// Rundler is free software: you can redistribute it and/or modify it under the
// terms of the GNU Lesser General Public License as published by the Free Software
// Foundation, either version 3 of the License, or (at your option) any later version.
//
// Rundler is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
// See the GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along with Rundler.
// If not, see https://www.gnu.org/licenses/.

use std::{
    collections::{HashMap, VecDeque},
    sync::Arc,
};

use anyhow::Context;
use ethers::{
    abi::{AbiDecode, RawLog},
    prelude::EthEvent,
    types::{
        spoof, Address, Bytes, Filter, GethDebugBuiltInTracerType, GethDebugTracerType,
        GethDebugTracingOptions, GethTrace, GethTraceFrame, Log, TransactionReceipt, H256, U256,
        U64,BigEndianHash,
    },
    utils::{to_checksum, hex},
};
use rundler_pool::PoolServer;
use rundler_provider::{EntryPoint, Provider };
use rundler_sim::{
    EstimationSettings, FeeEstimator, GasEstimate, GasEstimationError, GasEstimator,
    GasEstimatorImpl, PrecheckSettings, UserOperationOptionalGas,
};
use rundler_types::{
    contracts::i_entry_point::{
        IEntryPointCalls, UserOperationEventFilter, UserOperationRevertReasonFilter,
    },
    contracts::hc_helper::{HCHelper as HH2},
    contracts::simple_account::SimpleAccount,
    UserOperation,
};
use rundler_utils::{eth::log_to_raw_log, log::LogOnError};
use tracing::Level;

use super::error::{EthResult, EthRpcError, ExecutionRevertedWithBytesData};
use crate::types::{RichUserOperation, RpcUserOperation, UserOperationReceipt};

use rundler_types::hybrid_compute;
//use ethers::types::BigEndianHash;

use jsonrpsee::{
    core::{client::ClientT, params::ObjectParams, JsonValue},
    http_client::{HttpClientBuilder},
};
use rundler_utils::eth;
//use std::backtrace::Backtrace;
/// Settings for the `eth_` API
#[derive(Clone, Debug)] // FIXME - can't Copy because of hc.node_http string
pub struct Settings {
    /// The number of blocks to look back for user operation events
    pub user_operation_event_block_distance: Option<u64>,
    /// HybridCompute info
    pub hc: hybrid_compute::HcCfg,
}

impl Settings {
    /// Create new settings for the `eth_` API
    pub fn new(
        block_distance: Option<u64>,
    ) -> Self {
        Self {
            user_operation_event_block_distance: block_distance,
	    hc: hybrid_compute::HC_CONFIG.lock().unwrap().clone(),
        }
    }
}

#[derive(Debug)]
struct EntryPointContext<P, E> {
    gas_estimator: GasEstimatorImpl<P, E>,
}

impl<P, E> EntryPointContext<P, E>
where
    P: Provider,
    E: EntryPoint,
{
    fn new(
        chain_id: u64,
        provider: Arc<P>,
        entry_point: E,
        estimation_settings: EstimationSettings,
        fee_estimator: FeeEstimator<P>,
    ) -> Self {
        let gas_estimator = GasEstimatorImpl::new(
            chain_id,
            provider,
            entry_point,
            estimation_settings,
            fee_estimator,
        );
        Self { gas_estimator }
    }
}

// Can't track down what's causing the gas differences between
// simulateHandleOps and SimulateValidation, so pad it and
// hope for the best. Unused gas will be refunded.
const VG_PAD:i32 = 20000;

#[derive(Debug)]
pub(crate) struct EthApi<P, E, PS> where E: EntryPoint {
    contexts_by_entry_point: HashMap<Address, EntryPointContext<P, E>>,
    provider: Arc<P>,
    chain_id: u64,
    pool: PS,
    settings: Settings,
}

impl<P, E, PS> EthApi<P, E, PS>
where
    P: Provider,
    E: EntryPoint,
    PS: PoolServer,
{
    pub(crate) fn new(
        provider: Arc<P>,
        entry_points: Vec<E>,
        chain_id: u64,
        pool: PS,
        settings: Settings,
        estimation_settings: EstimationSettings,
        precheck_settings: PrecheckSettings,
    ) -> Self
    where
        E: Clone,
    {
        let contexts_by_entry_point = entry_points
            .into_iter()
            .map(|entry_point| {
                (
                    entry_point.address(),
                    EntryPointContext::new(
                        chain_id,
                        Arc::clone(&provider),
                        entry_point,
                        estimation_settings,
                        FeeEstimator::new(
                            Arc::clone(&provider),
                            chain_id,
                            precheck_settings.priority_fee_mode,
                            precheck_settings.bundle_priority_fee_overhead_percent,
                        ),
                    ),
                )
            })
            .collect();

        Self {
            settings,
            contexts_by_entry_point,
            provider,
            chain_id,
            pool,
        }
    }

    pub(crate) async fn send_user_operation(
        &self,
        op: RpcUserOperation,
        entry_point: Address,
    ) -> EthResult<H256> {
        if !self.contexts_by_entry_point.contains_key(&entry_point) {
            return Err(EthRpcError::InvalidParams(
                "supplied entry point addr is not a known entry point".to_string(),
            ));
        }
	println!("HC send_user_operation {:?}", op);
        self.pool
            .add_op(entry_point, op.into())
            .await
            .map_err(EthRpcError::from)
            .log_on_error_level(Level::DEBUG, "failed to add op to the mempool")
    }

    // Verify that the trigger string came from the HCHelper contract
    async fn hc_verify_trigger(
        &self,
        context:&EntryPointContext<P, E>,
        op: UserOperationOptionalGas,
        key: H256,
        state_override: Option<spoof::State>,
    ) -> bool {
	let mut s2 = state_override.clone().unwrap_or_default();
	let hc_addr = self.settings.hc.helper_addr;

	// Set a 1-byte value which will trigger a special revert code
	let val_vrfy = "0xff00000000000000000000000000000000000000000000000000000000000002".parse::<Bytes>().unwrap();
	s2.account(hc_addr).store(key, H256::from_slice(&val_vrfy).into_uint());

	let result_v = context
	  .gas_estimator
	  .estimate_op_gas(op.clone(), s2.clone(), None)
	  .await;
	println!("HC HC result_v {:?}", result_v);
        match result_v {
            Err(GasEstimationError::RevertInCallWithMessage(msg)) => {
                if msg == "_HC_VRFY".to_string() {
                    return true;
		}
	    }
	    _ => {}
        }
        false
    }

    // Generate and cache an offchain operation, then re-run the userOp simulation
    // with its data inserted into the HCHelper contract's state.
    async fn hc_simulate_response(
        &self,
        context:&EntryPointContext<P, E>,
	op: UserOperationOptionalGas,
	state_override: Option<spoof::State>,
	revert_data: &Bytes,
    ) -> Result<GasEstimate, GasEstimationError> {

	let s2 = state_override.unwrap_or_default();

	let es = EstimationSettings {
              max_verification_gas: 0,
              max_call_gas: 0,
              max_simulate_handle_ops_gas: 0,
              validation_estimation_gas_fee: 0,
        };
        let hh = op.clone().into_user_operation(&es).op_hc_hash();
	println!("HC api.rs hh {:?}", hh);

	let ep_addr = hybrid_compute::hc_ep_addr(revert_data);

	let n_key:U256 = op.nonce >> 64;
        let at_price = op.max_priority_fee_per_gas;
	let hc_nonce = context.gas_estimator.entry_point.get_nonce(op.sender, n_key).await.unwrap();
	let err_nonce = context.gas_estimator.entry_point.get_nonce(self.settings.hc.sys_account, n_key).await.unwrap();
	println!("HC hc_nonce {:?} op_nonce {:?} n_key {:?}", hc_nonce, op.nonce, n_key);
	let p2 = eth::new_provider(&self.settings.hc.node_http, None)?;

	let hx = HH2::new(self.settings.hc.helper_addr, p2.clone());
	let url = hx.registered_callers(ep_addr).await.expect("url_decode").1;
	println!("HC registered_caller url {:?}", url);

        let cc = HttpClientBuilder::default().build(url);  // could specify a request_timeout() here.
        if cc.is_err() {
            return Err(GasEstimationError::RevertInValidation("Invalid URL registered for HC".to_string()));
        }

	let m = hex::encode(hybrid_compute::hc_selector(revert_data));
	let sub_key = hybrid_compute::hc_sub_key(revert_data);
	let sk_hex = hex::encode(sub_key);
	let map_key = hybrid_compute::hc_map_key(revert_data);

	println!("HC api.rs sk_hex {:?} mk {:?}", sk_hex, map_key);

	let payload = hex::encode(hybrid_compute::hc_req_payload(revert_data));
	let n_bytes:[u8; 32] = (hc_nonce).into();
	let src_n = hex::encode(n_bytes);
	let src_addr = hex::encode(op.sender);

	let oo_n_key:U256 = U256::from_big_endian(op.sender.as_fixed_bytes());
	let oo_nonce = context.gas_estimator.entry_point.get_nonce(ep_addr, oo_n_key).await.unwrap();

        let ha_owner = SimpleAccount::new(ep_addr, p2).owner().await;

        if ha_owner.is_err() {
            return Err(GasEstimationError::RevertInValidation("Failed to look up HybridAccount owner".to_string()));
        }

        const REQ_VERSION:&str = "0.2";

	let mut params = ObjectParams::new();
	let _ = params.insert("ver", REQ_VERSION);
	let _ = params.insert("sk", sk_hex);
	let _ = params.insert("src_addr", src_addr);
	let _ = params.insert("src_nonce", src_n);
	let _ = params.insert("oo_nonce", oo_nonce);
	let _ = params.insert("payload", payload);

        let resp: Result<HashMap<String,JsonValue>, _> = cc.unwrap().request(&m, params).await;

        println!("HC resp {:?}", resp);
        let err_hc:hybrid_compute::HcErr;

        match resp {
	    Ok(resp) => {
	        if resp.contains_key("success") && resp.contains_key("response") && resp.contains_key("signature") &&
		resp["success"].is_boolean() && resp["response"].is_string() && resp["signature"].is_string() {
                    let op_success = resp["success"].as_bool().unwrap();
	            let resp_hex = resp["response"].as_str().unwrap();
	            let sig_hex:String = resp["signature"].as_str().unwrap().into();
	            let hc_res:Bytes = hex::decode(resp_hex).unwrap().into();
	            //println!("HC api.rs do_op result sk {:?} success {:?} res {:?}", sub_key, op_success, hc_res);

                    err_hc = hybrid_compute::external_op(hh, op.sender, hc_nonce, op_success, &hc_res, sub_key, ep_addr, sig_hex, oo_nonce, map_key, &self.settings.hc, ha_owner.unwrap(), err_nonce).await;
                } else {
	            err_hc = hybrid_compute::HcErr{code: 3, message:"HC03: Decode Error".to_string()};
		}
	    },
	    Err(error) => {
                match error {
                    jsonrpsee::core::Error::Call(e)  => {
			err_hc = hybrid_compute::HcErr{code: 2, message:"HC02: Call error: ".to_owned() + e.message()};
	            },
                    jsonrpsee::core::Error::Transport(e) => {
			if e.to_string().contains("Connection refused") ||
			  e.to_string().contains("status code: 5") { // look for 500-class HTTP errors
		            err_hc = hybrid_compute::HcErr{code: 6, message:"HC06: ".to_owned() + &e.to_string()};
			} else {
		            err_hc = hybrid_compute::HcErr{code: 2, message:"HC02: ".to_owned() + &e.to_string()};
			}
		    },
                    jsonrpsee::core::Error::RequestTimeout => {
                        err_hc = hybrid_compute::HcErr{code: 6, message:"HC06: RequestTimeout".to_string()};
		    },
                    jsonrpsee::core::Error::Custom(e) => {
			err_hc = hybrid_compute::HcErr{code: 2, message:"HC02: Custom error:".to_owned() + &e.to_string()};
		    },
		    other => {
		      println!("HC unmatched error {:?}", other);
	              err_hc = hybrid_compute::HcErr{code: 4, message:"HC04: Unrecognized Error:".to_owned() + &other.to_string()};
		    }
                }
	    }
	}

        if err_hc.code != 0 {
            println!("HC api.rs calling err_op {:?}", err_hc.message);
	    hybrid_compute::err_op(hh, context.gas_estimator.entry_point.address(), err_hc.clone(), sub_key, op.sender, hc_nonce, err_nonce, map_key, &self.settings.hc).await;
	}

        let s2 = hybrid_compute::get_hc_op_statediff(hh, s2);
	let result2 = context
            .gas_estimator
            .estimate_op_gas(op, s2, None)
            .await;
	println!("HC result2 {:?}", result2);
	if result2.is_ok() {
	    println!("HC api.rs Ok gas result2 = {:?}", result2);
	    let r3 = result2.unwrap();

	    let op_tmp = hybrid_compute::get_hc_ent(hh).unwrap().user_op;
	    let op_tmp_2: UserOperationOptionalGas = UserOperationOptionalGas {
	        sender: op_tmp.sender,
		nonce: op_tmp.nonce,
		init_code: op_tmp.init_code,
		call_data: op_tmp.call_data,
		call_gas_limit: Some(op_tmp.call_gas_limit),
		verification_gas_limit: Some(op_tmp.verification_gas_limit),
		pre_verification_gas: Some(op_tmp.pre_verification_gas),
		max_fee_per_gas: Some(op_tmp.max_fee_per_gas),
		max_priority_fee_per_gas: Some(op_tmp.max_priority_fee_per_gas),
		paymaster_and_data: op_tmp.paymaster_and_data,
		signature: op_tmp.signature,
	    };

            // The op_tmp_2 below specifies a 0 gas price, but we need to estimate the L1 fee at the
            // price offered by real userOperation which will be paying for it.

	    let r2a = context
                .gas_estimator
                .estimate_op_gas(op_tmp_2.clone(), spoof::State::default(), at_price)
                .await;

            if let Err(GasEstimationError::RevertInValidation(ref r2_err)) = r2a {
                let msg = "HC04: Offchain validation failed: ".to_string() + &r2_err;
                return Err(GasEstimationError::RevertInValidation(msg));
            };
            let r2 = r2a?;

            // The current formula used to estimate gas usage in the offchain_rpc service
            // sometimes underestimates the true cost. For now all we can do is error here.
            if r2.call_gas_limit > op_tmp_2.call_gas_limit.unwrap() {
                let msg = "HC04: Offchain call_gas_limit too low".to_string();
                return Err(GasEstimationError::RevertInValidation(msg));
            }

            let offchain_gas = r2.pre_verification_gas + r2.verification_gas_limit + r2.call_gas_limit;

            let mut cleanup_keys:Vec<H256> = Vec::new();
	    cleanup_keys.push(map_key);
	    let c_nonce = context.gas_estimator.entry_point.get_nonce(self.settings.hc.sys_account, U256::zero()).await.unwrap();
	    let cleanup_op = hybrid_compute::rr_op(&self.settings.hc, c_nonce, cleanup_keys.clone()).await;
	    let op_tmp_4: UserOperationOptionalGas = UserOperationOptionalGas {
	        sender: cleanup_op.sender,
		nonce: cleanup_op.nonce,
		init_code: cleanup_op.init_code,
		call_data: cleanup_op.call_data,
		call_gas_limit: Some(cleanup_op.call_gas_limit),
		verification_gas_limit: Some(cleanup_op.verification_gas_limit),
		pre_verification_gas: Some(cleanup_op.pre_verification_gas),
		max_fee_per_gas: Some(cleanup_op.max_fee_per_gas),
		max_priority_fee_per_gas: Some(cleanup_op.max_priority_fee_per_gas),
		paymaster_and_data: cleanup_op.paymaster_and_data,
		signature: cleanup_op.signature,
	    };
	    //println!("HC op_tmp_4 {:?} {:?}", op_tmp_4, cleanup_keys);
	    let r4 = context.gas_estimator.estimate_op_gas(op_tmp_4, spoof::State::default(), at_price).await?;
            let cleanup_gas = r4.pre_verification_gas + r4.verification_gas_limit + r4.call_gas_limit;
            let op_gas = r3.pre_verification_gas + r3.verification_gas_limit + r3.call_gas_limit;
	    println!("HC api.rs offchain_gas estimate {:?} sum {:?}", r2, offchain_gas);
	    println!("HC api.rs userop_gas estimate   {:?} sum {:?}", r3, op_gas);
	    println!("HC api.rs cleanup_gas estimate  {:?} sum {:?}", r4, cleanup_gas);

            let needed_pvg = r3.pre_verification_gas + offchain_gas;
            hybrid_compute::hc_set_pvg(hh, needed_pvg, offchain_gas + cleanup_gas + offchain_gas);

            if err_hc.code != 0 {
                return Err(GasEstimationError::RevertInValidation(err_hc.message));
	    }

            let total_gas = needed_pvg + (r3.verification_gas_limit + VG_PAD) + r3.call_gas_limit;
            if total_gas > U256::from(25_000_000) { // Approaching the block gas limit
                let err_msg:String = "Excessive HC total_gas estimate = ".to_owned() + &total_gas.to_string();
                return Err(GasEstimationError::RevertInValidation(err_msg));
            }

	    return Ok(GasEstimate {
	        pre_verification_gas: needed_pvg,
	        verification_gas_limit: r3.verification_gas_limit,
	        call_gas_limit: r3.call_gas_limit,
	    });
	} else {
            return result2;
        }
    }

    pub(crate) async fn estimate_user_operation_gas(
        &self,
        op: UserOperationOptionalGas,
        entry_point: Address,
        state_override: Option<spoof::State>,
    ) -> EthResult<GasEstimate> {
        let context = self
            .contexts_by_entry_point
            .get(&entry_point)
            .ok_or_else(|| {
                EthRpcError::InvalidParams(
                    "supplied entry_point address is not a known entry point".to_string(),
                )
            })?;

	//println!("HC api.rs Before estimate_gas {:?}", op);
        let mut result = context
            .gas_estimator
            .estimate_op_gas(op.clone(), state_override.clone().unwrap_or_default(), None)
            .await;
	println!("HC api.rs estimate_gas result1 {:?}", result);
        match result {
	  Ok(_) => {}
	  Err(GasEstimationError::RevertInCallWithBytes(ref revert_data)) => {
	    if hybrid_compute::check_trigger(revert_data) {
              let bn = self.provider.get_block_number().await.unwrap();
              println!("HC api.rs HC trigger at bn {}", bn);

	      let map_key = hybrid_compute::hc_map_key(revert_data);
	      let key:H256 = hybrid_compute::hc_storage_key(map_key);

	      if self.hc_verify_trigger(context, op.clone(), key, state_override.clone()).await {
	        result = self.hc_simulate_response(context, op, state_override, revert_data).await;
	      } else {
	        println!("HC did not get expected _HC_VRFY");
	      }
	    }
	  }
	  Err(_) => {}
	}

        match result {
            Ok(estimate) => Ok(GasEstimate {
                pre_verification_gas: estimate.pre_verification_gas,
	        verification_gas_limit: estimate.verification_gas_limit + VG_PAD,
	        call_gas_limit: estimate.call_gas_limit,
            }),
            Err(GasEstimationError::RevertInValidation(message)) => {
                Err(EthRpcError::EntryPointValidationRejected(message))?
            }
            Err(GasEstimationError::RevertInCallWithMessage(message)) => {
                Err(EthRpcError::ExecutionReverted(message))?
            }
            Err(GasEstimationError::RevertInCallWithBytes(b)) => {
                Err(EthRpcError::ExecutionRevertedWithBytes(
                    ExecutionRevertedWithBytesData { revert_data: b },
                ))?
            }
            Err(GasEstimationError::Other(error)) => Err(error)?,
        }
    }

    pub(crate) async fn get_user_operation_by_hash(
        &self,
        hash: H256,
    ) -> EthResult<Option<RichUserOperation>> {
        if hash == H256::zero() {
            return Err(EthRpcError::InvalidParams(
                "Missing/invalid userOpHash".to_string(),
            ));
        }

        // check for the user operation both in the pool and mined on chain
        let mined_fut = self.get_mined_user_operation_by_hash(hash);
        let pending_fut = self.get_pending_user_operation_by_hash(hash);
        let (mined, pending) = tokio::join!(mined_fut, pending_fut);

        // mined takes precedence over pending
        if let Ok(Some(mined)) = mined {
            Ok(Some(mined))
        } else if let Ok(Some(pending)) = pending {
            Ok(Some(pending))
        } else if mined.is_err() || pending.is_err() {
            // if either futures errored, and the UO was not found, return the errors
            Err(EthRpcError::Internal(anyhow::anyhow!(
                "error fetching user operation by hash: mined: {:?}, pending: {:?}",
                mined.err().map(|e| e.to_string()).unwrap_or_default(),
                pending.err().map(|e| e.to_string()).unwrap_or_default(),
            )))
        } else {
            // not found in either pool or mined
            Ok(None)
        }
    }

    pub(crate) async fn get_user_operation_receipt(
        &self,
        hash: H256,
    ) -> EthResult<Option<UserOperationReceipt>> {
        if hash == H256::zero() {
            return Err(EthRpcError::InvalidParams(
                "Missing/invalid userOpHash".to_string(),
            ));
        }

        // Get event associated with hash (need to check all entry point addresses associated with this API)
        let log = self
            .get_user_operation_event_by_hash(hash)
            .await
            .context("should have fetched user ops by hash")?;

        let Some(log) = log else { return Ok(None) };
        let entry_point = log.address;

        // If the event is found, get the TX receipt
        let tx_hash = log.transaction_hash.context("tx_hash should be present")?;
        let tx_receipt = self
            .provider
            .get_transaction_receipt(tx_hash)
            .await
            .context("should have fetched tx receipt")?
            .context("Failed to fetch tx receipt")?;

        // Return null if the tx isn't included in the block yet
        if tx_receipt.block_hash.is_none() && tx_receipt.block_number.is_none() {
            return Ok(None);
        }

        // Filter receipt logs to match just those belonging to the user op
        let filtered_logs =
            EthApi::<P, E, PS>::filter_receipt_logs_matching_user_op(&log, &tx_receipt)
                .context("should have found receipt logs matching user op")?;

        // Decode log and find failure reason if not success
        let uo_event = self
            .decode_user_operation_event(log)
            .context("should have decoded user operation event")?;
        let reason: String = if uo_event.success {
            "".to_owned()
        } else {
            EthApi::<P, E, PS>::get_user_operation_failure_reason(&tx_receipt.logs, hash)
                .context("should have found revert reason if tx wasn't successful")?
                .unwrap_or_default()
        };

        Ok(Some(UserOperationReceipt {
            user_op_hash: hash,
            entry_point: entry_point.into(),
            sender: uo_event.sender.into(),
            nonce: uo_event.nonce,
            paymaster: uo_event.paymaster.into(),
            actual_gas_cost: uo_event.actual_gas_cost,
            actual_gas_used: uo_event.actual_gas_used,
            success: uo_event.success,
            logs: filtered_logs,
            receipt: tx_receipt,
            reason,
        }))
    }

    pub(crate) async fn supported_entry_points(&self) -> EthResult<Vec<String>> {
        Ok(self
            .contexts_by_entry_point
            .keys()
            .map(|ep| to_checksum(ep, None))
            .collect())
    }

    pub(crate) async fn chain_id(&self) -> EthResult<U64> {
        Ok(self.chain_id.into())
    }

    async fn get_mined_user_operation_by_hash(
        &self,
        hash: H256,
    ) -> EthResult<Option<RichUserOperation>> {
        // Get event associated with hash (need to check all entry point addresses associated with this API)
        let event = self
            .get_user_operation_event_by_hash(hash)
            .await
            .log_on_error("should have successfully queried for user op events by hash")?;

        let Some(event) = event else { return Ok(None) };

        // If the event is found, get the TX and entry point
        let transaction_hash = event
            .transaction_hash
            .context("tx_hash should be present")?;

        let tx = self
            .provider
            .get_transaction(transaction_hash)
            .await
            .context("should have fetched tx from provider")?
            .context("should have found tx")?;

        // We should return null if the tx isn't included in the block yet
        if tx.block_hash.is_none() && tx.block_number.is_none() {
            return Ok(None);
        }
        let to = tx
            .to
            .context("tx.to should be present on transaction containing user operation event")?;

        // Find first op matching the hash
        let user_operation = if self.contexts_by_entry_point.contains_key(&to) {
            self.get_user_operations_from_tx_data(tx.input)
                .into_iter()
                .find(|op| op.op_hash(to, self.chain_id) == hash)
                .context("matching user operation should be found in tx data")?
        } else {
            self.trace_find_user_operation(transaction_hash, hash)
                .await
                .context("error running trace")?
                .context("should have found user operation in trace")?
        };

        Ok(Some(RichUserOperation {
            user_operation: user_operation.into(),
            entry_point: event.address.into(),
            block_number: Some(
                tx.block_number
                    .map(|n| U256::from(n.as_u64()))
                    .unwrap_or_default(),
            ),
            block_hash: Some(tx.block_hash.unwrap_or_default()),
            transaction_hash: Some(transaction_hash),
        }))
    }

    async fn get_pending_user_operation_by_hash(
        &self,
        hash: H256,
    ) -> EthResult<Option<RichUserOperation>> {
        let res = self
            .pool
            .get_op_by_hash(hash)
            .await
            .map_err(EthRpcError::from)?;
        Ok(res.map(|op| RichUserOperation {
            user_operation: op.uo.into(),
            entry_point: op.entry_point.into(),
            block_number: None,
            block_hash: None,
            transaction_hash: None,
        }))
    }

    async fn get_user_operation_event_by_hash(&self, hash: H256) -> EthResult<Option<Log>> {
        let to_block = self.provider.get_block_number().await?;

        let from_block = match self.settings.user_operation_event_block_distance {
            Some(distance) => to_block.saturating_sub(distance),
            None => 0,
        };

        let filter = Filter::new()
            .address::<Vec<Address>>(
                self.contexts_by_entry_point
                    .iter()
                    .map(|ep| *ep.0)
                    .collect(),
            )
            .event(&UserOperationEventFilter::abi_signature())
            .from_block(from_block)
            .to_block(to_block)
            .topic1(hash);

        let logs = self.provider.get_logs(&filter).await?;
        Ok(logs.into_iter().next())
    }

    fn get_user_operations_from_tx_data(&self, tx_data: Bytes) -> Vec<UserOperation> {
        let entry_point_calls = match IEntryPointCalls::decode(tx_data) {
            Ok(entry_point_calls) => entry_point_calls,
            Err(_) => return vec![],
        };

        match entry_point_calls {
            IEntryPointCalls::HandleOps(handle_ops_call) => handle_ops_call.ops,
            IEntryPointCalls::HandleAggregatedOps(handle_aggregated_ops_call) => {
                handle_aggregated_ops_call
                    .ops_per_aggregator
                    .into_iter()
                    .flat_map(|ops| ops.user_ops)
                    .collect()
            }
            _ => vec![],
        }
    }

    fn decode_user_operation_event(&self, log: Log) -> EthResult<UserOperationEventFilter> {
        Ok(UserOperationEventFilter::decode_log(&log_to_raw_log(log))
            .context("log should be a user operation event")?)
    }

    /// This method takes a user operation event and a transaction receipt and filters out all the logs
    /// relevant to the user operation. Since there are potentially many user operations in a transaction,
    /// we want to find all the logs (including the user operation event itself) that are sandwiched between
    /// ours and the one before it that wasn't ours.
    /// eg. reference_log: UserOp(hash_moldy) logs: \[...OtherLogs, UserOp(hash1), ...OtherLogs, UserOp(hash_moldy), ...OtherLogs\]
    /// -> logs: logs\[(idx_of_UserOp(hash1) + 1)..=idx_of_UserOp(hash_moldy)\]
    ///
    /// topic\[0\] == event name
    /// topic\[1\] == user operation hash
    ///
    /// NOTE: we can't convert just decode all the logs as user operations and filter because we still want all the other log types
    ///
    fn filter_receipt_logs_matching_user_op(
        reference_log: &Log,
        tx_receipt: &TransactionReceipt,
    ) -> EthResult<Vec<Log>> {
        let mut start_idx = 0;
        let mut end_idx = tx_receipt.logs.len() - 1;
        let logs = &tx_receipt.logs;

        let is_ref_user_op = |log: &Log| {
            log.topics[0] == reference_log.topics[0]
                && log.topics[1] == reference_log.topics[1]
                && log.address == reference_log.address
        };

        let is_user_op_event = |log: &Log| log.topics[0] == reference_log.topics[0];

        let mut i = 0;
        while i < logs.len() {
            if i < end_idx && is_user_op_event(&logs[i]) && !is_ref_user_op(&logs[i]) {
                start_idx = i;
            } else if is_ref_user_op(&logs[i]) {
                end_idx = i;
            }

            i += 1;
        }

        if !is_ref_user_op(&logs[end_idx]) {
            return Err(EthRpcError::Internal(anyhow::anyhow!(
                "fatal: no user ops found in tx receipt ({start_idx},{end_idx})"
            )));
        }

        let start_idx = if start_idx == 0 { 0 } else { start_idx + 1 };
        Ok(logs[start_idx..=end_idx].to_vec())
    }

    fn get_user_operation_failure_reason(
        logs: &[Log],
        user_op_hash: H256,
    ) -> EthResult<Option<String>> {
        let revert_reason_evt: Option<UserOperationRevertReasonFilter> = logs
            .iter()
            .filter(|l| l.topics.len() > 1 && l.topics[1] == user_op_hash)
            .map_while(|l| {
                UserOperationRevertReasonFilter::decode_log(&RawLog {
                    topics: l.topics.clone(),
                    data: l.data.to_vec(),
                })
                .ok()
            })
            .next();

        Ok(revert_reason_evt.map(|r| r.revert_reason.to_string()))
    }

    /// This method takes a transaction hash and a user operation hash and returns the full user operation if it exists.
    /// This is meant to be used when a user operation event is found in the logs of a transaction, but the top level call
    /// wasn't to an entrypoint, so we need to trace the transaction to find the user operation by inspecting each call frame
    /// and returning the user operation that matches the hash.
    async fn trace_find_user_operation(
        &self,
        tx_hash: H256,
        user_op_hash: H256,
    ) -> EthResult<Option<UserOperation>> {
        // initial call wasn't to an entrypoint, so we need to trace the transaction to find the user operation
        let trace_options = GethDebugTracingOptions {
            tracer: Some(GethDebugTracerType::BuiltInTracer(
                GethDebugBuiltInTracerType::CallTracer,
            )),
            ..Default::default()
        };
	println!("HC trace_find_user_operation pre");
        let trace = self
            .provider
            .debug_trace_transaction(tx_hash, trace_options)
            .await
            .context("should have fetched trace from provider")?;
	println!("HC trace_find_user_operation post {:?}", trace);

        // breadth first search for the user operation in the trace
        let mut frame_queue = VecDeque::new();

        if let GethTrace::Known(GethTraceFrame::CallTracer(call_frame)) = trace {
            frame_queue.push_back(call_frame);
        }

        while let Some(call_frame) = frame_queue.pop_front() {
            // check if the call is to an entrypoint, if not enqueue the child calls if any
            if let Some(to) = call_frame
                .to
                .as_ref()
                .and_then(|to| to.as_address())
                .filter(|to| self.contexts_by_entry_point.contains_key(to))
            {
                // check if the user operation is in the call frame
                if let Some(uo) = self
                    .get_user_operations_from_tx_data(call_frame.input)
                    .into_iter()
                    .find(|op| op.op_hash(*to, self.chain_id) == user_op_hash)
                {
                    return Ok(Some(uo));
                }
            } else if let Some(calls) = call_frame.calls {
                frame_queue.extend(calls)
            }
        }

        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use ethers::{
        abi::AbiEncode,
        types::{Log, Transaction, TransactionReceipt},
        utils::keccak256,
    };
    use mockall::predicate::eq;
    use rundler_pool::{MockPoolServer, PoolOperation};
    use rundler_provider::{MockEntryPoint, MockProvider};
    use rundler_sim::PriorityFeeMode;
    use rundler_types::contracts::i_entry_point::HandleOpsCall;

    use super::*;

    const UO_OP_TOPIC: &str = "user-op-event-topic";

    #[test]
    fn test_filter_receipt_logs_when_at_beginning_of_list() {
        let reference_log = given_log(UO_OP_TOPIC, "moldy-hash");
        let receipt = given_receipt(vec![
            given_log("other-topic", "some-hash"),
            reference_log.clone(),
            given_log(UO_OP_TOPIC, "other-hash"),
            given_log(UO_OP_TOPIC, "another-hash"),
        ]);

        let result =
            EthApi::<MockProvider, MockEntryPoint, MockPoolServer>::filter_receipt_logs_matching_user_op(
                &reference_log,
                &receipt,
            );

        assert!(result.is_ok(), "{}", result.unwrap_err());
        let result = result.unwrap();
        assert_eq!(result, receipt.logs[0..=1]);
    }

    #[test]
    fn test_filter_receipt_logs_when_in_middle_of_list() {
        let reference_log = given_log(UO_OP_TOPIC, "moldy-hash");
        let receipt = given_receipt(vec![
            given_log("other-topic", "some-hash"),
            given_log(UO_OP_TOPIC, "other-hash"),
            given_log("another-topic", "some-hash"),
            given_log("another-topic-2", "some-hash"),
            reference_log.clone(),
            given_log(UO_OP_TOPIC, "another-hash"),
        ]);

        let result =
            EthApi::<MockProvider, MockEntryPoint, MockPoolServer>::filter_receipt_logs_matching_user_op(
                &reference_log,
                &receipt,
            );

        assert!(result.is_ok(), "{}", result.unwrap_err());
        let result = result.unwrap();
        assert_eq!(result, receipt.logs[2..=4]);
    }

    #[test]
    fn test_filter_receipt_logs_when_at_end_of_list() {
        let reference_log = given_log(UO_OP_TOPIC, "moldy-hash");
        let receipt = given_receipt(vec![
            given_log("other-topic", "some-hash"),
            given_log(UO_OP_TOPIC, "other-hash"),
            given_log(UO_OP_TOPIC, "another-hash"),
            given_log("another-topic", "some-hash"),
            given_log("another-topic-2", "some-hash"),
            reference_log.clone(),
        ]);

        let result =
            EthApi::<MockProvider, MockEntryPoint, MockPoolServer>::filter_receipt_logs_matching_user_op(
                &reference_log,
                &receipt,
            );

        assert!(result.is_ok(), "{}", result.unwrap_err());
        let result = result.unwrap();
        assert_eq!(result, receipt.logs[3..=5]);
    }

    #[test]
    fn test_filter_receipt_logs_skips_event_from_different_address() {
        let reference_log = given_log(UO_OP_TOPIC, "moldy-hash");
        let mut reference_log_w_different_address = reference_log.clone();
        reference_log_w_different_address.address = Address::from_low_u64_be(0x1234);

        let receipt = given_receipt(vec![
            given_log("other-topic", "some-hash"),
            given_log(UO_OP_TOPIC, "other-hash"),
            given_log(UO_OP_TOPIC, "another-hash"),
            reference_log_w_different_address,
            given_log("another-topic", "some-hash"),
            given_log("another-topic-2", "some-hash"),
            reference_log.clone(),
        ]);

        let result =
            EthApi::<MockProvider, MockEntryPoint, MockPoolServer>::filter_receipt_logs_matching_user_op(
                &reference_log,
                &receipt,
            );

        assert!(result.is_ok(), "{}", result.unwrap_err());
        let result = result.unwrap();
        assert_eq!(result, receipt.logs[4..=6]);
    }

    #[test]
    fn test_filter_receipt_logs_includes_multiple_sets_of_ref_uo() {
        let reference_log = given_log(UO_OP_TOPIC, "moldy-hash");

        let receipt = given_receipt(vec![
            given_log("other-topic", "some-hash"),
            given_log(UO_OP_TOPIC, "other-hash"),
            given_log("other-topic-2", "another-hash"),
            reference_log.clone(),
            given_log("another-topic", "some-hash"),
            given_log("another-topic-2", "some-hash"),
            reference_log.clone(),
            given_log(UO_OP_TOPIC, "other-hash"),
        ]);

        let result =
            EthApi::<MockProvider, MockEntryPoint, MockPoolServer>::filter_receipt_logs_matching_user_op(
                &reference_log,
                &receipt,
            );

        assert!(result.is_ok(), "{}", result.unwrap_err());
        let result = result.unwrap();
        assert_eq!(result, receipt.logs[2..=6]);
    }

    #[test]
    fn test_filter_receipt_logs_when_not_found() {
        let reference_log = given_log(UO_OP_TOPIC, "moldy-hash");
        let receipt = given_receipt(vec![
            given_log("other-topic", "some-hash"),
            given_log(UO_OP_TOPIC, "other-hash"),
            given_log(UO_OP_TOPIC, "another-hash"),
            given_log("another-topic", "some-hash"),
            given_log("another-topic-2", "some-hash"),
        ]);

        let result =
            EthApi::<MockProvider, MockEntryPoint, MockPoolServer>::filter_receipt_logs_matching_user_op(
                &reference_log,
                &receipt,
            );

        assert!(result.is_err(), "{:?}", result.unwrap());
    }

    #[tokio::test]
    async fn test_get_user_op_by_hash_pending() {
        let ep = Address::random();
        let uo = UserOperation::default();
        let hash = uo.op_hash(ep, 1);

        let po = PoolOperation {
            uo: uo.clone(),
            entry_point: ep,
            ..Default::default()
        };

        let mut pool = MockPoolServer::default();
        pool.expect_get_op_by_hash()
            .with(eq(hash))
            .times(1)
            .returning(move |_| Ok(Some(po.clone())));

        let mut provider = MockProvider::default();
        provider.expect_get_logs().returning(move |_| Ok(vec![]));
        provider.expect_get_block_number().returning(|| Ok(1000));

        let mut entry_point = MockEntryPoint::default();
        entry_point.expect_address().returning(move || ep);

        let api = create_api(provider, entry_point, pool);
        let res = api.get_user_operation_by_hash(hash).await.unwrap();
        let ro = RichUserOperation {
            user_operation: uo.into(),
            entry_point: ep.into(),
            block_number: None,
            block_hash: None,
            transaction_hash: None,
        };
        assert_eq!(res, Some(ro));
    }

    #[tokio::test]
    async fn test_get_user_op_by_hash_mined() {
        let ep = Address::random();
        let uo = UserOperation::default();
        let hash = uo.op_hash(ep, 1);
        let block_number = 1000;
        let block_hash = H256::random();

        let mut pool = MockPoolServer::default();
        pool.expect_get_op_by_hash()
            .with(eq(hash))
            .returning(move |_| Ok(None));

        let mut provider = MockProvider::default();
        provider.expect_get_block_number().returning(|| Ok(1000));

        let tx_data: Bytes = IEntryPointCalls::HandleOps(HandleOpsCall {
            beneficiary: Address::zero(),
            ops: vec![uo.clone()],
        })
        .encode()
        .into();
        let tx = Transaction {
            to: Some(ep),
            input: tx_data,
            block_number: Some(block_number.into()),
            block_hash: Some(block_hash),
            ..Default::default()
        };
        let tx_hash = tx.hash();
        let log = Log {
            address: ep,
            transaction_hash: Some(tx_hash),
            ..Default::default()
        };

        provider
            .expect_get_logs()
            .returning(move |_| Ok(vec![log.clone()]));
        provider
            .expect_get_transaction()
            .with(eq(tx_hash))
            .returning(move |_| Ok(Some(tx.clone())));

        let mut entry_point = MockEntryPoint::default();
        entry_point.expect_address().returning(move || ep);

        let api = create_api(provider, entry_point, pool);
        let res = api.get_user_operation_by_hash(hash).await.unwrap();
        let ro = RichUserOperation {
            user_operation: uo.into(),
            entry_point: ep.into(),
            block_number: Some(block_number.into()),
            block_hash: Some(block_hash),
            transaction_hash: Some(tx_hash),
        };
        assert_eq!(res, Some(ro));
    }

    #[tokio::test]
    async fn test_get_user_op_by_hash_not_found() {
        let ep = Address::random();
        let uo = UserOperation::default();
        let hash = uo.op_hash(ep, 1);

        let mut pool = MockPoolServer::default();
        pool.expect_get_op_by_hash()
            .with(eq(hash))
            .times(1)
            .returning(move |_| Ok(None));

        let mut provider = MockProvider::default();
        provider.expect_get_logs().returning(move |_| Ok(vec![]));
        provider.expect_get_block_number().returning(|| Ok(1000));

        let mut entry_point = MockEntryPoint::default();
        entry_point.expect_address().returning(move || ep);

        let api = create_api(provider, entry_point, pool);
        let res = api.get_user_operation_by_hash(hash).await.unwrap();
        assert_eq!(res, None);
    }

    fn given_log(topic_0: &str, topic_1: &str) -> Log {
        Log {
            topics: vec![
                keccak256(topic_0.as_bytes()).into(),
                keccak256(topic_1.as_bytes()).into(),
            ],
            ..Default::default()
        }
    }

    fn given_receipt(logs: Vec<Log>) -> TransactionReceipt {
        TransactionReceipt {
            logs,
            ..Default::default()
        }
    }

    fn create_api(
        provider: MockProvider,
        ep: MockEntryPoint,
        pool: MockPoolServer,
    ) -> EthApi<MockProvider, MockEntryPoint, MockPoolServer> {
        let mut contexts_by_entry_point = HashMap::new();
        let provider = Arc::new(provider);
        contexts_by_entry_point.insert(
            ep.address(),
            EntryPointContext::new(
                1,
                Arc::clone(&provider),
                ep,
                EstimationSettings {
                    max_verification_gas: 1_000_000,
                    max_call_gas: 1_000_000,
                    max_simulate_handle_ops_gas: 1_000_000,
                    validation_estimation_gas_fee: 1_000_000_000_000,
                },
                FeeEstimator::new(
                    Arc::clone(&provider),
                    1,
                    PriorityFeeMode::BaseFeePercent(0),
                    0,
                ),
            ),
        );
        EthApi {
            contexts_by_entry_point,
            provider,
            chain_id: 1,
            pool,
            settings: Settings::new(None),
        }
    }
}
