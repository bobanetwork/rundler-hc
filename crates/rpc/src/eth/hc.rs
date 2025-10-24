use alloy_primitives::{
    aliases::U192,
    hex,
    map::{FbBuildHasher, HashMap},
    Address, Bytes, B256, U128, U256,
};
use alloy_rpc_types_eth::state::AccountOverride;
use alloy_sol_types::SolValue;
use jsonrpsee::{
    core::{client::ClientT, params::ObjectParams, JsonValue},
    http_client::HttpClientBuilder,
};
use rundler_contracts::v0_7::{IHCHelper, ISimpleAccount};
use rundler_provider::StateOverride;
use rundler_types::{
    hybrid_compute, UserOperation, UserOperationOptionalGas, UserOperationVariant,
};

use crate::{
    eth::{EntryPointRouter, EthResult, EthRpcError},
    types::{RpcGasEstimate, RpcGasEstimateV0_6, RpcGasEstimateV0_7},
};
// Can't track down what's causing the gas differences between
// simulateHandleOps and SimulateValidation, so pad it and
// hope for the best. Unused gas will be refunded.
pub(crate) const VG_PAD: i32 = 20000;

// FIXME - Workaround for another occasional failure.
pub(crate) const PVG_PAD: i32 = 10000;

#[derive(Clone)]
pub(crate) struct HcApi {
    pub cfg: hybrid_compute::HcCfg,
    router: EntryPointRouter,
}

impl HcApi {
    pub(crate) fn new(r: EntryPointRouter) -> Self {
        Self {
            cfg: hybrid_compute::HC_CONFIG.lock().unwrap().clone(),
            router: r,
        }
    }

    pub(crate) async fn hc_verify_trigger(
        &self,
        //context:&EntryPointContext<P, E>,
        entry_point: Address,
        op: UserOperationOptionalGas,
        key: B256,
        state_override: Option<StateOverride>,
    ) -> bool {
        let mut s2 = state_override.clone().unwrap_or_default();
        let hc_addr = self.cfg.helper_addr;

        let mut hm = HashMap::with_hasher(FbBuildHasher::<32>::default());

        // Set a 1-byte value which will trigger a special revert code
        let val_vrfy = "0xff00000000000000000000000000000000000000000000000000000000000002"
            .parse::<Bytes>()
            .unwrap();
        //s2.account(hc_addr).store(key, B256::from_slice(&val_vrfy));
        hm.insert(key, B256::from_slice(&val_vrfy));
        let ao = AccountOverride {
            state_diff: Some(hm),
            ..Default::default()
        };

        s2.insert(hc_addr, ao);
        let result_v = self
            .router
            .estimate_gas(&entry_point, op.clone(), Some(s2), None)
            .await;

        //println!("HC result_v {:?}", result_v);
        if let Err(EthRpcError::ExecutionReverted(ref msg)) = result_v {
            if *msg == "_HC_VRFY" {
                return true;
            }
        }

        false
    }

    // Generate and cache an offchain operation, then re-run the userOp simulation
    // with its data inserted into the HCHelper contract's state.
    pub(crate) async fn hc_simulate_response(
        &self,
        //context:&EntryPointContext<P, E>,
        entry_point: Address,
        op: UserOperationOptionalGas,
        state_override: Option<StateOverride>,
        revert_data: &Bytes,
    ) -> EthResult<RpcGasEstimate> {
        let s2 = state_override.unwrap_or_default();

        let hh = op.hc_hash(&self.cfg.chain_spec);
        let op_t: UserOperationVariant = op.into_variant(&self.cfg.chain_spec);

        let ep_addr = hybrid_compute::hc_ha_addr(revert_data);

        let n_key: U256 = op_t.nonce() >> 64;
        let at_price = Some(op_t.max_priority_fee_per_gas());
        let hc_nonce = self
            .router
            .get_nonce(&entry_point, op_t.sender(), n_key.to::<U192>())
            .await
            .unwrap();

        let err_nonce = self
            .router
            .get_nonce(&entry_point, self.cfg.sys_account, n_key.to::<U192>())
            .await
            .unwrap();

        let p2 = rundler_provider::new_alloy_provider(&self.cfg.node_http, 120)?;
        let m = hex::encode(hybrid_compute::hc_selector(revert_data));

        let sub_key = hybrid_compute::hc_sub_key(revert_data);
        let sk_hex = hex::encode(sub_key);
        let map_key = hybrid_compute::hc_map_key(revert_data);

        let payload = hex::encode(hybrid_compute::hc_req_payload(revert_data));
        let n_bytes: B256 = hc_nonce.into();
        let src_n = hex::encode(n_bytes);
        let src_addr = hex::encode(op_t.sender());

        let mut is_registration = false;

        // check for "_register(address,string)"
        let url = match m.as_str() {
            hybrid_compute::REG_SELECTOR => {
                is_registration = true;
                let (addr, new_url) = <(Address, String)>::abi_decode_sequence(
                    &hybrid_compute::hc_req_payload(revert_data),
                )
                .unwrap();
                println!("HC Registration request for {:?} -> {:?}", addr, new_url);
                new_url
            }
            _ => {
                let hx = IHCHelper::new(self.cfg.helper_addr, p2.clone());
                let url_response = hx.RegisteredCallers(ep_addr).call().await;
                url_response.expect("url_decode").url
            }
        };

        let cc = HttpClientBuilder::default().build(&url); // could specify a request_timeout() here.
        if cc.is_err() {
            return Err(EthRpcError::Internal(anyhow::anyhow!(
                "Invalid URL registered for HC"
            )));
        }

        println!(
            "HC api.rs processing hc_hash {:?}, url {:?} ({:?}, {:?}, {:?}, {:?}, {:?})",
            hh,
            url,
            hc_nonce,
            err_nonce,
            op_t.nonce(),
            sk_hex,
            map_key,
        );
        let oo_n_key: U256 = U256::from_be_slice(op_t.sender().as_slice());

        let oo_nonce = self
            .router
            .get_nonce(&entry_point, ep_addr, oo_n_key.to::<U192>())
            .await
            .unwrap();

        let sa = ISimpleAccount::new(ep_addr, p2);
        let ha_result = sa.owner().call().await;

        if ha_result.is_err() {
            return Err(EthRpcError::Internal(anyhow::anyhow!(
                "Failed to look up HybridAccount owner"
            )));
        }
        let ha_owner = ha_result.unwrap();

        // This version parameter tells the offchain RPC which version of the
        // AA contracts are being used. This affects the hashing algorithm needed
        // to generate an offchain signature.
        // V6 EP -> 0.2 REQ_VERSION was removed; only V7 is presently supported.
        const REQ_VERSION_V7: &str = "0.3";

        let _is_v7 = match self.router.get_ep_version(&entry_point)? {
            rundler_types::EntryPointVersion::V0_7 => true,
            rundler_types::EntryPointVersion::V0_6 => {
                return Err(EthRpcError::Internal(anyhow::anyhow!(
                    "HC04: EntryPoint version 0.6 is not supported"
                )))
            }
            rundler_types::EntryPointVersion::Unspecified => {
                return Err(EthRpcError::Internal(anyhow::anyhow!(
                    "HC04: Unknown EntryPoint version"
                )))
            }
        };

        let mut params = ObjectParams::new();
        let _ = params.insert("ver", REQ_VERSION_V7);
        let _ = params.insert("sk", sk_hex);
        let _ = params.insert("src_addr", src_addr);
        let _ = params.insert("src_nonce", src_n);
        let _ = params.insert("oo_nonce", oo_nonce);
        let _ = params.insert("payload", payload);

        let resp: Result<HashMap<String, JsonValue>, _> = cc.unwrap().request(&m, params).await;

        println!("HC offchain response for {:?} = {:?}", hh, resp);
        let err_hc: hybrid_compute::HcErr;

        match resp {
            Ok(resp) => {
                if resp.contains_key("success")
                    && resp.contains_key("response")
                    && resp.contains_key("signature")
                    && resp["success"].is_boolean()
                    && resp["response"].is_string()
                    && resp["signature"].is_string()
                {
                    let op_success = resp["success"].as_bool().unwrap();
                    let resp_hex = resp["response"].as_str().unwrap();
                    let sig_hex: String = resp["signature"].as_str().unwrap().into();
                    let hc_res: Bytes = hex::decode(resp_hex).unwrap().into();

                    if is_registration {
                        if let Ok(reg_ok) = resp_hex.parse::<U256>() {
                            println!(
                                "HC Self-registration op_success {:?}, reg_ok {:?}",
                                op_success, reg_ok
                            );
                            // Placeholder for additional checks. Bundler could choose to deny certain
                            // requests, substituting a system error. Bundler could detect repeated failures
                            // for a particular URL or particular source contract and auto-blacklist. Etc.
                        } else {
                            let msg = "HC04: Bad self-registration response".to_owned();
                            return Err(EthRpcError::Internal(anyhow::anyhow!(msg)));
                        }
                    }

                    err_hc = hybrid_compute::external_op(
                        entry_point,
                        hh,
                        op_t.sender(),
                        hc_nonce,
                        op_success,
                        &hc_res,
                        sub_key,
                        ep_addr,
                        sig_hex,
                        oo_nonce,
                        map_key,
                        &self.cfg,
                        ha_owner,
                        err_nonce,
                    )
                    .await;
                } else {
                    err_hc = hybrid_compute::HcErr {
                        code: 3,
                        message: "HC03: Decode Error".to_string(),
                    };
                }
            }
            Err(error) => {
                match error {
                    jsonrpsee::core::ClientError::Call(e) => {
                        err_hc = hybrid_compute::HcErr {
                            code: 2,
                            message: "HC02: Call error: ".to_owned() + e.message(),
                        };
                    }
                    jsonrpsee::core::ClientError::Transport(e) => {
                        if e.to_string().contains("Connection refused")
                            || e.to_string().contains("status code: 5")
                        {
                            // look for 500-class HTTP errors
                            err_hc = hybrid_compute::HcErr {
                                code: 6,
                                message: "HC06: ".to_owned() + &e.to_string(),
                            };
                        } else {
                            err_hc = hybrid_compute::HcErr {
                                code: 2,
                                message: "HC02: ".to_owned() + &e.to_string(),
                            };
                        }
                    }
                    jsonrpsee::core::ClientError::RequestTimeout => {
                        err_hc = hybrid_compute::HcErr {
                            code: 6,
                            message: "HC06: RequestTimeout".to_string(),
                        };
                    }
                    jsonrpsee::core::ClientError::Custom(e) => {
                        err_hc = hybrid_compute::HcErr {
                            code: 2,
                            message: "HC02: Custom error:".to_owned() + &e.to_string(),
                        };
                    }
                    other => {
                        println!("HC unmatched error {:?}", other);
                        err_hc = hybrid_compute::HcErr {
                            code: 4,
                            message: "HC04: Unrecognized Error:".to_owned() + &other.to_string(),
                        };
                    }
                }
            }
        }

        if err_hc.code != 0 {
            println!(
                "HC api.rs calling err_op {:?} / {:?}",
                err_hc.code, err_hc.message
            );
            hybrid_compute::err_op(
                hh,
                entry_point,
                err_hc.clone(),
                sub_key,
                op_t.sender(),
                hc_nonce,
                err_nonce,
                map_key,
                &self.cfg,
            )
            .await;
        }

        let s2 = hybrid_compute::get_hc_op_statediff(hh, s2);
        let result2 = self
            .router
            .estimate_gas(&entry_point, op.clone(), Some(s2), None)
            .await;
        //println!("HC api.rs estimate_gas 2 for hc_hash {:?} = {:?}", hh, result2);

        let r3: RpcGasEstimateV0_7;
        if result2.is_ok() {
            let r3a = result2.unwrap();
            match r3a {
                RpcGasEstimate::V0_6(_est) => {
                    let msg = "HC04: Internal error".to_owned();
                    return Err(EthRpcError::Internal(anyhow::anyhow!(msg)));
                }
                RpcGasEstimate::V0_7(est) => {
                    r3 = RpcGasEstimateV0_7 {
                        pre_verification_gas: est.pre_verification_gas,
                        call_gas_limit: est.call_gas_limit,
                        verification_gas_limit: est.verification_gas_limit,
                        paymaster_verification_gas_limit: est.paymaster_verification_gas_limit,
                    };
                }
            }

            let op_tmp_2 = hybrid_compute::get_hc_ent(hh).unwrap().user_op;

            // The op_tmp_2 below specifies a 0 gas price, but we need to estimate the L1 fee at the
            // price offered by real userOperation which will be paying for it.

            let r2a = self
                .router
                .estimate_gas(
                    &entry_point,
                    op_tmp_2.clone(),
                    Some(StateOverride::default()),
                    at_price,
                )
                .await;

            if let Err(EthRpcError::ExecutionReverted(ref r2_err)) = r2a {
                // FIXME
                println!("HC op_tmp_2 gas estimation failed (RevertInValidation)");
                let msg = "HC04: Offchain validation failed: ".to_string() + r2_err;
                return Err(EthRpcError::Internal(anyhow::anyhow!(msg)));
            };

            let r2: RpcGasEstimateV0_7 = match r2a? {
                RpcGasEstimate::V0_7(est) => est,
                RpcGasEstimate::V0_6(est) => RpcGasEstimateV0_7 {
                    pre_verification_gas: est.pre_verification_gas,
                    call_gas_limit: est.call_gas_limit,
                    verification_gas_limit: est.verification_gas_limit,
                    paymaster_verification_gas_limit: None,
                },
            };

            // The current formula used to estimate gas usage in the offchain_rpc service
            // sometimes underestimates the true cost. For now all we can do is error here.
            if r2.call_gas_limit.to::<u128>()
                > op_tmp_2.into_variant(&self.cfg.chain_spec).call_gas_limit()
            {
                println!("HC op_tmp_2 failed, call_gas_limit too low");
                let msg = "HC04: Offchain call_gas_limit too low".to_string();
                return Err(EthRpcError::Internal(anyhow::anyhow!(msg)));
            }

            let offchain_gas =
                r2.pre_verification_gas + r2.verification_gas_limit + r2.call_gas_limit;

            let cleanup_keys: Vec<B256> = vec![map_key];
            let c_nonce = self
                .router
                .get_nonce(&entry_point, self.cfg.sys_account, U192::ZERO)
                .await
                .unwrap();
            let cleanup_op =
                hybrid_compute::rr_op(&self.cfg, entry_point, c_nonce, cleanup_keys.clone()).await;

            //println!("HC cleanup_op {:?} {:?}", cleanup_op, cleanup_keys);
            let r4a = self
                .router
                .estimate_gas(
                    &entry_point,
                    // rundler_types::UserOperationOptionalGas::V0_6(op_tmp_4),
                    cleanup_op,
                    Some(StateOverride::default()),
                    at_price,
                )
                .await;
            let r4: RpcGasEstimateV0_7 = match r4a? {
                RpcGasEstimate::V0_7(est) => est,
                RpcGasEstimate::V0_6(est) => RpcGasEstimateV0_7 {
                    pre_verification_gas: est.pre_verification_gas,
                    call_gas_limit: est.call_gas_limit,
                    verification_gas_limit: est.verification_gas_limit,
                    paymaster_verification_gas_limit: None,
                },
            };

            let cleanup_gas =
                r4.pre_verification_gas + r4.verification_gas_limit + r4.call_gas_limit;
            let op_gas = r3.pre_verification_gas + r3.verification_gas_limit + r3.call_gas_limit;
            println!(
                "HC api.rs offchain_gas estimate {:?} sum {:?}",
                r2, offchain_gas
            );
            println!("HC api.rs userop_gas estimate   {:?} sum {:?}", r3, op_gas);
            println!(
                "HC api.rs cleanup_gas estimate  {:?} sum {:?}",
                r4, cleanup_gas
            );

            let needed_pvg = r3.pre_verification_gas + offchain_gas;
            println!(
                "HC api.rs needed_pvg for hc_hash {:?} is {:?} ({:?} + {:?})",
                hh, needed_pvg, r3.pre_verification_gas, offchain_gas
            );

            let offchain_pvg = offchain_gas
                .saturating_add(offchain_gas)
                .saturating_add(cleanup_gas);

            hybrid_compute::hc_set_pvg(hh, needed_pvg.to::<u128>(), offchain_pvg.to::<u128>());

            if err_hc.code != 0 && err_hc.code != 128 {
                return Err(EthRpcError::Internal(anyhow::anyhow!(err_hc.message)));
            }

            let total_gas = needed_pvg
                .saturating_add(r3.verification_gas_limit)
                .saturating_add(U128::from(VG_PAD))
                .saturating_add(r3.call_gas_limit);
            if total_gas > U128::from(25_000_000) {
                // Approaching the block gas limit
                let err_msg: String =
                    "Excessive HC total_gas estimate = ".to_owned() + &total_gas.to_string();
                return Err(EthRpcError::Internal(anyhow::anyhow!(err_msg)));
            }

            Ok(RpcGasEstimateV0_7 {
                pre_verification_gas: needed_pvg.saturating_add(U128::from(PVG_PAD)),
                verification_gas_limit: r3.verification_gas_limit,
                call_gas_limit: r3.call_gas_limit,
                paymaster_verification_gas_limit: r3.paymaster_verification_gas_limit,
            }
            .into())
        } else {
            println!(
                "HC WARNING api.rs estimate_gas result2 for hc_hash {:?} = {:?}",
                hh, result2
            );
            result2
        }

        //Err(EthRpcError::Internal(anyhow::anyhow!("TEMP_ERR".to_string())))
    }

    pub(crate) async fn hc_estimate_gas(
        &self,
        entry_point: Address,
        op: UserOperationOptionalGas,
        state_override: Option<StateOverride>,
    ) -> EthResult<RpcGasEstimate> {
        let hc_hash = op.hc_hash(&self.cfg.chain_spec);
        println!(
            "HC api.rs calling estimate_gas for hc_hash {:?} op {:?}",
            hc_hash, op
        );

        let mut result = self
            .router
            .estimate_gas(&entry_point, op.clone(), state_override.clone(), None)
            .await;

        match result {
            Ok(ref estimate) => {
                println!(
                    "HC api.rs estimate_gas Ok for hc_hash {:?}: {:?}",
                    hc_hash, result
                );
                if let RpcGasEstimate::V0_6(estimate6) = estimate {
                    return Ok(RpcGasEstimateV0_6 {
                        pre_verification_gas: estimate6
                            .pre_verification_gas
                            .saturating_add(U128::from(PVG_PAD)),
                        verification_gas_limit: estimate6
                            .verification_gas_limit
                            .saturating_add(U128::from(VG_PAD)),
                        call_gas_limit: estimate6.call_gas_limit,
                    }
                    .into());
                } else if let RpcGasEstimate::V0_7(estimate7) = estimate {
                    return Ok(RpcGasEstimateV0_7 {
                        pre_verification_gas: estimate7
                            .pre_verification_gas
                            .saturating_add(U128::from(PVG_PAD)),
                        verification_gas_limit: estimate7
                            .verification_gas_limit
                            .saturating_add(U128::from(VG_PAD)),
                        call_gas_limit: estimate7.call_gas_limit,
                        paymaster_verification_gas_limit: estimate7
                            .paymaster_verification_gas_limit,
                    }
                    .into());
                }
            }
            Err(EthRpcError::ExecutionRevertedWithBytes(ref r)) => {
                if hybrid_compute::check_trigger(&r.revert_data) {
                    let map_key = hybrid_compute::hc_map_key(&r.revert_data);
                    let key: B256 = hybrid_compute::hc_storage_key(map_key);

                    if self
                        .hc_verify_trigger(entry_point, op.clone(), key, state_override.clone())
                        .await
                    {
                        result = self
                            .hc_simulate_response(entry_point, op, state_override, &r.revert_data)
                            .await;
                        println!(
                            "HC api.rs Final estimate_gas for hc_hash {:?} = {:?}",
                            hc_hash, result
                        );
                    } else {
                        println!("HC WARNING did not get expected _HC_VRFY for {:?}", hc_hash);
                        let msg = "HC04: Failed to verify trigger event".to_owned();
                        return Err(EthRpcError::Internal(anyhow::anyhow!(msg)));
                    }
                } else {
                    println!(
                        "HC trigger prefix not detected in revert data for {:?}",
                        hc_hash
                    );
                }
            }
            Err(_) => {}
        }
        result
    }
}
