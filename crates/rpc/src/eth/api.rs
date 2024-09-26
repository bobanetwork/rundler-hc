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
    collections::{HashMap},
    future::Future,
    pin::Pin,
};

use ethers::{
    types::{spoof, Address, H256, U64},
    utils::{to_checksum, hex},
};
use futures_util::future;
use rundler_types::{
    chain::ChainSpec, pool::Pool, UserOperation, UserOperationOptionalGas, UserOperationVariant,
    contracts::v0_6::hc_helper::{HCHelper as HH2},
    contracts::v0_6::simple_account::SimpleAccount,
   
};
use rundler_utils::log::LogOnError;
use tracing::Level;

use super::{
    error::{EthResult, EthRpcError},
    router::EntryPointRouter,
};
use crate::types::{RpcGasEstimate, RpcUserOperationByHash, RpcUserOperationReceipt};

use rundler_types::hybrid_compute;
use ethers::types::{U256,Bytes};
use jsonrpsee::{
    core::{client::ClientT, params::ObjectParams, JsonValue},
    http_client::{HttpClientBuilder},
};
use crate::types::RpcGasEstimateV0_6;

/// Settings for the `eth_` API
#[derive(Copy, Clone, Debug)]
pub struct Settings {
    /// The number of blocks to look back for user operation events
    pub user_operation_event_block_distance: Option<u64>,
}

impl Settings {
    /// Create new settings for the `eth_` API
    pub fn new(block_distance: Option<u64>) -> Self {
        Self {
            user_operation_event_block_distance: block_distance,
        }
    }
}

// Can't track down what's causing the gas differences between
// simulateHandleOps and SimulateValidation, so pad it and
// hope for the best. Unused gas will be refunded.
const VG_PAD:i32 = 20000;

// FIXME - Workaround for another occasional failure.
const PVG_PAD:i32 = 5000;

pub(crate) struct EthApi<P> {
    pub(crate) chain_spec: ChainSpec,
    pool: P,
    router: EntryPointRouter,
    hc: hybrid_compute::HcCfg,
}

impl<P> EthApi<P>
where
    P: Pool,
{
    pub(crate) fn new(chain_spec: ChainSpec, router: EntryPointRouter, pool: P) -> Self {
	let hc = hybrid_compute::HC_CONFIG.lock().unwrap().clone();
        Self {
            router,
            pool,
            chain_spec,
            hc,
        }
    }

    pub(crate) async fn send_user_operation(
        &self,
        op: UserOperationVariant,
        entry_point: Address,
    ) -> EthResult<H256> {
	println!("HC send_user_operation {:?}", op);
        let bundle_size = op.single_uo_bundle_size_bytes();
        if bundle_size > self.chain_spec.max_transaction_size_bytes {
            return Err(EthRpcError::InvalidParams(format!(
                "User operation in bundle size {} exceeds max transaction size {}",
                bundle_size, self.chain_spec.max_transaction_size_bytes
            )));
        }

        self.router.check_and_get_route(&entry_point, &op)?;

        self.pool
            .add_op(entry_point, op)
            .await
            .map_err(EthRpcError::from)
            .log_on_error_level(Level::DEBUG, "failed to add op to the mempool")
    }
    async fn hc_verify_trigger(
        &self,
        //context:&EntryPointContext<P, E>,
        entry_point: Address,
        op: UserOperationOptionalGas,
        key: H256,
        state_override: Option<spoof::State>,
    ) -> bool {
        let mut s2 = state_override.clone().unwrap_or_default();
	let hc_addr = self.hc.helper_addr;

	// Set a 1-byte value which will trigger a special revert code
	let val_vrfy = "0xff00000000000000000000000000000000000000000000000000000000000002".parse::<Bytes>().unwrap();
	s2.account(hc_addr).store(key, H256::from_slice(&val_vrfy));

	let result_v = self.router
            .estimate_gas(&entry_point, op.clone(), Some(s2), None)
            .await;

	println!("HC result_v {:?}", result_v);
        match result_v {
            Err(EthRpcError::ExecutionReverted(ref msg)) => {
                if *msg == "_HC_VRFY".to_string() {
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
        //context:&EntryPointContext<P, E>,
        entry_point: Address,
	op: UserOperationOptionalGas,
	state_override: Option<spoof::State>,
	revert_data: &Bytes,
    ) -> EthResult<RpcGasEstimate> {
	let s2 = state_override.unwrap_or_default();
	//let es = EstimationSettings {
        //      max_verification_gas: 0,
        //      max_call_gas: 0,
        //      max_simulate_handle_ops_gas: 0,
        //      validation_estimation_gas_fee: 0,
        //};
        let op6:rundler_types::v0_6::UserOperationOptionalGas = op.clone().into();
        
        let hh = op6.clone().into_user_operation(U256::from(0),U256::from(0)).hc_hash();
	println!("HC api.rs hh {:?}", hh);

	let ep_addr = hybrid_compute::hc_ep_addr(revert_data);

	let n_key:U256 = op6.nonce >> 64;
        let at_price = op6.max_priority_fee_per_gas;
	//let hc_nonce = context.gas_estimator.entry_point.get_nonce(op6.sender, n_key).await.unwrap();
	let hc_nonce = self.router.get_nonce(&entry_point, op6.sender, n_key).await.unwrap();

	let err_nonce = self.router.get_nonce(&entry_point, self.hc.sys_account, n_key).await.unwrap();
	println!("HC hc_nonce {:?} err_nonce {:?} op_nonce {:?} n_key {:?}", hc_nonce, err_nonce, op6.nonce, n_key);
	let p2 = rundler_provider::new_provider(&self.hc.node_http, None)?;

	let hx = HH2::new(self.hc.helper_addr, p2.clone());
	let url = hx.registered_callers(ep_addr).await.expect("url_decode").1;
	println!("HC registered_caller url {:?}", url);

        let cc = HttpClientBuilder::default().build(url);  // could specify a request_timeout() here.
        if cc.is_err() {
            return Err(EthRpcError::Internal(anyhow::anyhow!("Invalid URL registered for HC")));
        }
	let m = hex::encode(hybrid_compute::hc_selector(revert_data));
	let sub_key = hybrid_compute::hc_sub_key(revert_data);
	let sk_hex = hex::encode(sub_key);
	let map_key = hybrid_compute::hc_map_key(revert_data);

	println!("HC api.rs sk_hex {:?} mk {:?}", sk_hex, map_key);

	let payload = hex::encode(hybrid_compute::hc_req_payload(revert_data));
	let n_bytes:[u8; 32] = (hc_nonce).into();
	let src_n = hex::encode(n_bytes);
	let src_addr = hex::encode(op6.sender);

	let oo_n_key:U256 = U256::from_big_endian(op6.sender.as_fixed_bytes());
	let oo_nonce = self.router.get_nonce(&entry_point, ep_addr, oo_n_key).await.unwrap();

        let ha_owner = SimpleAccount::new(ep_addr, p2).owner().await;

        if ha_owner.is_err() {
            return Err(EthRpcError::Internal(anyhow::anyhow!("Failed to look up HybridAccount owner")));
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

                    err_hc = hybrid_compute::external_op(hh, op6.sender, hc_nonce, op_success, &hc_res, sub_key, ep_addr, sig_hex, oo_nonce, map_key, &self.hc, ha_owner.unwrap(), err_nonce).await;
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
	    hybrid_compute::err_op(hh, entry_point, err_hc.clone(), sub_key, op6.sender, hc_nonce, err_nonce, map_key, &self.hc).await;
	}

        let s2 = hybrid_compute::get_hc_op_statediff(hh, s2);
	let result2 = self.router
            .estimate_gas(&entry_point, op.clone(), Some(s2), None)
            .await;
	println!("HC result2 {:?}", result2);
        let r3:RpcGasEstimateV0_6;
	if result2.is_ok() {
	    println!("HC api.rs Ok gas result2 = {:?}", result2);
	    let r3a = result2.unwrap();
            match r3a {
                RpcGasEstimate::V0_6(abc) => {
                    r3 = abc;
                },
                _ => {
                    return Err(EthRpcError::Internal(anyhow::anyhow!("HC04 user_op gas estimation failed")));
                }
            }

	    let op_tmp = hybrid_compute::get_hc_ent(hh).unwrap().user_op;
	    let op_tmp_2: rundler_types::v0_6::UserOperationOptionalGas = rundler_types::v0_6::UserOperationOptionalGas {
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

	    let r2a = self.router
                .estimate_gas(&entry_point,  rundler_types::UserOperationOptionalGas::V0_6(op_tmp_2.clone()), Some(spoof::State::default()), at_price)
                .await;

            if let Err(EthRpcError::ExecutionReverted(ref r2_err)) = r2a { // FIXME
                println!("HC op_tmp_2 gas estimation failed (RevertInValidation)");
                let msg = "HC04: Offchain validation failed: ".to_string() + &r2_err;
                return Err(EthRpcError::Internal(anyhow::anyhow!(msg)));
            };
            
            let r2:RpcGasEstimateV0_6;
            match r2a? {
                RpcGasEstimate::V0_6(abc) => {
                    r2 = abc;
                },
                _ => {
                    return Err(EthRpcError::Internal(anyhow::anyhow!("HC04 offchain_op gas estimation failed")));
                }
            }

            // The current formula used to estimate gas usage in the offchain_rpc service
            // sometimes underestimates the true cost. For now all we can do is error here.
            if r2.call_gas_limit > op_tmp_2.call_gas_limit.unwrap() {
                println!("HC op_tmp_2 failed, call_gas_limit too low");
                let msg = "HC04: Offchain call_gas_limit too low".to_string();
                return Err(EthRpcError::Internal(anyhow::anyhow!(msg)));
            }

            let offchain_gas = r2.pre_verification_gas + r2.verification_gas_limit + r2.call_gas_limit;

            let mut cleanup_keys:Vec<H256> = Vec::new();
	    cleanup_keys.push(map_key);
	    let c_nonce = self.router.get_nonce(&entry_point, self.hc.sys_account, U256::zero()).await.unwrap();
	    let cleanup_op = hybrid_compute::rr_op(&self.hc, c_nonce, cleanup_keys.clone()).await;
	    let op_tmp_4: rundler_types::v0_6::UserOperationOptionalGas = rundler_types::v0_6::UserOperationOptionalGas {
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
	    println!("HC op_tmp_4 {:?} {:?}", op_tmp_4, cleanup_keys);
	    let r4a = self.router.estimate_gas(&entry_point, rundler_types::UserOperationOptionalGas::V0_6(op_tmp_4), Some(spoof::State::default()), at_price).await;
            let r4:RpcGasEstimateV0_6;
            match r4a? {
                RpcGasEstimate::V0_6(abc) => {
                    r4 = abc;
                },
                _ => {
                    return Err(EthRpcError::Internal(anyhow::anyhow!("HC04 cleanup_op gas estimation failed")));
                }
            }

            let cleanup_gas = r4.pre_verification_gas + r4.verification_gas_limit + r4.call_gas_limit;
            let op_gas = r3.pre_verification_gas + r3.verification_gas_limit + r3.call_gas_limit;
	    println!("HC api.rs offchain_gas estimate {:?} sum {:?}", r2, offchain_gas);
	    println!("HC api.rs userop_gas estimate   {:?} sum {:?}", r3, op_gas);
	    println!("HC api.rs cleanup_gas estimate  {:?} sum {:?}", r4, cleanup_gas);

            let needed_pvg = r3.pre_verification_gas + offchain_gas;
            println!("HC needed_pvg {:?} = {:?} + {:?}", needed_pvg, r3.pre_verification_gas, offchain_gas);

            hybrid_compute::hc_set_pvg(hh, needed_pvg, offchain_gas + cleanup_gas + offchain_gas);

            if err_hc.code != 0 {
                return Err(EthRpcError::Internal(anyhow::anyhow!(err_hc.message)));
	    }

            let total_gas = needed_pvg + (r3.verification_gas_limit + VG_PAD) + r3.call_gas_limit;
            if total_gas > U256::from(25_000_000) { // Approaching the block gas limit
                let err_msg:String = "Excessive HC total_gas estimate = ".to_owned() + &total_gas.to_string();
                return Err(EthRpcError::Internal(anyhow::anyhow!(err_msg)));
            }

	    return Ok(RpcGasEstimateV0_6 {
	        pre_verification_gas: (needed_pvg + PVG_PAD),
	        verification_gas_limit: r3.verification_gas_limit,
	        call_gas_limit: r3.call_gas_limit,
	    }.into());
	} else {
            return result2;
        }
    }

    pub(crate) async fn estimate_user_operation_gas(
        &self,
        op: UserOperationOptionalGas,
        entry_point: Address,
        state_override: Option<spoof::State>,
    ) -> EthResult<RpcGasEstimate> {
        let bundle_size = op.single_uo_bundle_size_bytes();
        if bundle_size > self.chain_spec.max_transaction_size_bytes {
            return Err(EthRpcError::InvalidParams(format!(
                "User operation in bundle size {} exceeds max transaction size {}",
                bundle_size, self.chain_spec.max_transaction_size_bytes
            )));
        }

        let mut result = self.router
            .estimate_gas(&entry_point, op.clone(), state_override.clone(), None)
            .await;

	println!("HC api.rs estimate_gas result1 {:?}", result);
        match result {
	    Ok(ref estimate) => {
                match estimate {
                    RpcGasEstimate::V0_6(estimate6) => {
                        return Ok(RpcGasEstimateV0_6{
                            pre_verification_gas: estimate6.pre_verification_gas,
                            verification_gas_limit: estimate6.verification_gas_limit + VG_PAD,
                            call_gas_limit: estimate6.call_gas_limit,
                        }.into());
                    },
                    _ => {}
                }
            }
	    Err(EthRpcError::ExecutionRevertedWithBytes(ref r)) => { 
	        if hybrid_compute::check_trigger(&r.revert_data) {
                    let bn = 0; //self.provider.get_block_number().await.unwrap();
                    println!("HC api.rs HC trigger at bn {}", bn);

	            let map_key = hybrid_compute::hc_map_key(&r.revert_data);
	            let key:H256 = hybrid_compute::hc_storage_key(map_key);

	            if self.hc_verify_trigger(entry_point, op.clone(), key, state_override.clone()).await {
	              result = self.hc_simulate_response(entry_point, op, state_override, &r.revert_data).await;
	            } else {
	              println!("HC did not get expected _HC_VRFY");
                      let msg = "HC04: Failed to verify trigger event".to_owned();
                      return Err(EthRpcError::Internal(anyhow::anyhow!(msg)));
	            }
	        }
	    }
	    Err(_) => {}
	}
        result
    }

    pub(crate) async fn get_user_operation_by_hash(
        &self,
        hash: H256,
    ) -> EthResult<Option<RpcUserOperationByHash>> {
        if hash == H256::zero() {
            return Err(EthRpcError::InvalidParams(
                "Missing/invalid userOpHash".to_string(),
            ));
        }

        // check both entry points and pending for the user operation event
        #[allow(clippy::type_complexity)]
        let mut futs: Vec<
            Pin<Box<dyn Future<Output = EthResult<Option<RpcUserOperationByHash>>> + Send>>,
        > = vec![];

        for ep in self.router.entry_points() {
            futs.push(Box::pin(self.router.get_mined_by_hash(ep, hash)));
        }
        futs.push(Box::pin(self.get_pending_user_operation_by_hash(hash)));

        let results = future::try_join_all(futs).await?;
        Ok(results.into_iter().find_map(|x| x))
    }

    pub(crate) async fn get_user_operation_receipt(
        &self,
        hash: H256,
    ) -> EthResult<Option<RpcUserOperationReceipt>> {
        if hash == H256::zero() {
            return Err(EthRpcError::InvalidParams(
                "Missing/invalid userOpHash".to_string(),
            ));
        }

        let futs = self
            .router
            .entry_points()
            .map(|ep| self.router.get_receipt(ep, hash));

        let results = future::try_join_all(futs).await?;
        Ok(results.into_iter().find_map(|x| x))
    }

    pub(crate) async fn supported_entry_points(&self) -> EthResult<Vec<String>> {
        Ok(self
            .router
            .entry_points()
            .map(|ep| to_checksum(ep, None))
            .collect())
    }

    pub(crate) async fn chain_id(&self) -> EthResult<U64> {
        Ok(self.chain_spec.id.into())
    }

    async fn get_pending_user_operation_by_hash(
        &self,
        hash: H256,
    ) -> EthResult<Option<RpcUserOperationByHash>> {
        let res = self
            .pool
            .get_op_by_hash(hash)
            .await
            .map_err(EthRpcError::from)?;

        Ok(res.map(|op| RpcUserOperationByHash {
            user_operation: op.uo.into(),
            entry_point: op.entry_point.into(),
            block_number: None,
            block_hash: None,
            transaction_hash: None,
        }))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use ethers::{
        abi::AbiEncode,
        types::{Bytes, Log, Transaction},
    };
    use mockall::predicate::eq;
    use rundler_provider::{MockEntryPointV0_6, MockProvider};
    use rundler_sim::MockGasEstimator;
    use rundler_types::{
        contracts::v0_6::i_entry_point::{HandleOpsCall, IEntryPointCalls},
        pool::{MockPool, PoolOperation},
        v0_6::UserOperation,
        EntityInfos, UserOperation as UserOperationTrait, ValidTimeRange,
    };

    use super::*;
    use crate::eth::{
        EntryPointRouteImpl, EntryPointRouterBuilder, UserOperationEventProviderV0_6,
    };

    #[tokio::test]
    async fn test_get_user_op_by_hash_pending() {
        let ep = Address::random();
        let uo = UserOperation::default();
        let hash = uo.hash(ep, 1);

        let po = PoolOperation {
            uo: uo.clone().into(),
            entry_point: ep,
            aggregator: None,
            valid_time_range: ValidTimeRange::default(),
            expected_code_hash: H256::random(),
            sim_block_hash: H256::random(),
            sim_block_number: 1000,
            account_is_staked: false,
            entity_infos: EntityInfos::default(),
        };

        let mut pool = MockPool::default();
        pool.expect_get_op_by_hash()
            .with(eq(hash))
            .times(1)
            .returning(move |_| Ok(Some(po.clone())));

        let mut provider = MockProvider::default();
        provider.expect_get_logs().returning(move |_| Ok(vec![]));
        provider.expect_get_block_number().returning(|| Ok(1000));

        let mut entry_point = MockEntryPointV0_6::default();
        entry_point.expect_address().returning(move || ep);

        let api = create_api(provider, entry_point, pool, MockGasEstimator::default());
        let res = api.get_user_operation_by_hash(hash).await.unwrap();
        let ro = RpcUserOperationByHash {
            user_operation: UserOperationVariant::from(uo).into(),
            entry_point: ep.into(),
            block_number: None,
            block_hash: None,
            transaction_hash: None,
        };
        assert_eq!(res, Some(ro));
    }

    #[tokio::test]
    async fn test_get_user_op_by_hash_mined() {
        let cs = ChainSpec {
            id: 1,
            ..Default::default()
        };
        let ep = cs.entry_point_address_v0_6;
        let uo = UserOperation::default();
        let hash = uo.hash(ep, 1);
        let block_number = 1000;
        let block_hash = H256::random();

        let mut pool = MockPool::default();
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

        let mut entry_point = MockEntryPointV0_6::default();
        entry_point.expect_address().returning(move || ep);

        let api = create_api(provider, entry_point, pool, MockGasEstimator::default());
        let res = api.get_user_operation_by_hash(hash).await.unwrap();
        let ro = RpcUserOperationByHash {
            user_operation: UserOperationVariant::from(uo).into(),
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
        let hash = uo.hash(ep, 1);

        let mut pool = MockPool::default();
        pool.expect_get_op_by_hash()
            .with(eq(hash))
            .times(1)
            .returning(move |_| Ok(None));

        let mut provider = MockProvider::default();
        provider.expect_get_logs().returning(move |_| Ok(vec![]));
        provider.expect_get_block_number().returning(|| Ok(1000));

        let mut entry_point = MockEntryPointV0_6::default();
        entry_point.expect_address().returning(move || ep);

        let api = create_api(provider, entry_point, pool, MockGasEstimator::default());
        let res = api.get_user_operation_by_hash(hash).await.unwrap();
        assert_eq!(res, None);
    }

    fn create_api(
        provider: MockProvider,
        ep: MockEntryPointV0_6,
        pool: MockPool,
        gas_estimator: MockGasEstimator,
    ) -> EthApi<MockPool> {
        let ep = Arc::new(ep);
        let provider = Arc::new(provider);
        let chain_spec = ChainSpec {
            id: 1,
            ..Default::default()
        };

        let router = EntryPointRouterBuilder::default()
            .v0_6(EntryPointRouteImpl::new(
                ep.clone(),
                gas_estimator,
                UserOperationEventProviderV0_6::new(chain_spec.clone(), provider.clone(), None),
            ))
            .build();

        EthApi {
            router,
            chain_spec,
            pool,
            hc: hybrid_compute::HC_CONFIG.lock().unwrap().clone(),
        }
    }
}
