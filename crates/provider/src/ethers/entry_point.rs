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

use std::{ops::Deref, sync::Arc};

use anyhow::Context;
use ethers::{
    abi::AbiDecode,
    contract::{ContractError, FunctionCall},
    providers::{spoof, Middleware, RawCall},
    types::{
        transaction::eip2718::TypedTransaction, Address, BlockId, Bytes, Eip1559TransactionRequest,
        H256, U256,
    },
};

use rundler_types::hybrid_compute;


use rundler_types::{
    contracts::{
        i_entry_point::{ExecutionResult, FailedOp, IEntryPoint, SignatureValidationFailed},
        shared_types::UserOpsPerAggregator,
    },
    GasFees, UserOperation,
};
use rundler_utils::eth::{self, ContractRevertError};

use crate::traits::{EntryPoint, HandleOpsOut};

#[async_trait::async_trait]
impl<M> EntryPoint for IEntryPoint<M>
where
    M: Middleware + 'static,
{
    fn address(&self) -> Address {
        self.deref().address()
    }

    async fn simulate_validation(
        &self,
        user_op: UserOperation,
        max_validation_gas: u64,
    ) -> anyhow::Result<TypedTransaction> {
        //let pvg = user_op.pre_verification_gas;

        let gas_price = user_op.max_fee_per_gas;
        let mut tx = self
            .simulate_validation(user_op)
            .gas(U256::from(max_validation_gas))
            .tx;
	let from_addr = hybrid_compute::HC_CONFIG.lock().unwrap().from_addr;
	tx.set_from(from_addr);
	tx.set_gas_price(gas_price);
	//println!("HC entry_point.rs s_v {:?} {:?} {:?} {:?} gas_price", max_validation_gas, pvg, tx, gas_price);

        Ok(tx)
    }


    async fn call_handle_ops(
        &self,
        ops_per_aggregator: Vec<UserOpsPerAggregator>,
        beneficiary: Address,
        gas: U256,
    ) -> anyhow::Result<HandleOpsOut> {

        println!("HC entry_point call_handle_ops 1, len {:?} gas {:?}", ops_per_aggregator[0].user_ops.len(), gas);

	let result = get_handle_ops_call(self, ops_per_aggregator.clone(), beneficiary, gas)
            .call()
            .await;
        println!("HC entry_point call_handle_ops 2 result{:?}", result);
        let error = match result {
            Ok(()) => return Ok(HandleOpsOut::Success),
            Err(error) => error,
        };
        if let ContractError::Revert(revert_data) = &error {
            if let Ok(FailedOp { op_index, reason }) = FailedOp::decode(revert_data) {
                match &reason[..4] {
                    "AA95" => anyhow::bail!("Handle ops called with insufficient gas; {:?}", gas),
                    _ => {
                        println!("HC AA95 at index {:?}", op_index);
		        return Ok(HandleOpsOut::FailedOp(op_index.as_usize(), reason));
		    },
                }
            }
            if let Ok(failure) = SignatureValidationFailed::decode(revert_data) {
                return Ok(HandleOpsOut::SignatureValidationFailed(failure.aggregator));
            }
            // Special handling for a bug in the 0.6 entry point contract to detect the bug where
            // the `returndatacopy` opcode reverts due to a postOp revert and the revert data is too short.
            // See https://github.com/eth-infinitism/account-abstraction/pull/325 for more details.
            // NOTE: this error message is copied directly from Geth and assumes it will not change.
            if error.to_string().contains("return data out of bounds") {
                return Ok(HandleOpsOut::PostOpRevert);
            }
        }
        Err(error)?
    }

    async fn balance_of(
        &self,
        address: Address,
        block_id: Option<BlockId>,
    ) -> anyhow::Result<U256> {
        block_id
            .map_or(self.balance_of(address), |bid| {
                self.balance_of(address).block(bid)
            })
            .call()
            .await
            .context("entry point should return balance")
    }

    async fn call_spoofed_simulate_op(
        &self,
        op: UserOperation,
        target: Address,
        target_call_data: Bytes,
        block_hash: H256,
        gas: U256,
        spoofed_state: &spoof::State,
    ) -> anyhow::Result<Result<ExecutionResult, String>> {
        //println!("HC entry_point call_spoofed_simOp op {:?} {:?}", op.sender, op.nonce);

	let contract_error = self
            .simulate_handle_op(op, target, target_call_data)
            .block(block_hash)
            .gas(gas)
            .call_raw()
            .state(spoofed_state)
            .await
            .err()
            .context("simulateHandleOp succeeded, but should always revert")?;
        let revert_data = eth::get_revert_bytes(contract_error)
            .context("simulateHandleOps should return revert data")?;
//        println!("HC entry_point call_spoofed_simOp revertData {:?}", revert_data);
        return Ok(self.decode_simulate_handle_ops_revert(revert_data));
    }

    fn get_send_bundle_transaction(
        &self,
        ops_per_aggregator: Vec<UserOpsPerAggregator>,
        beneficiary: Address,
        gas: U256,
        gas_fees: GasFees,
    ) -> TypedTransaction {

        println!("HC starting get_send_bundle_transaction, len {} gas {:?} maxfees {:?}", ops_per_aggregator[0].user_ops.len(), gas, gas_fees);

        let tx: Eip1559TransactionRequest =
            get_handle_ops_call(self, ops_per_aggregator, beneficiary, gas)
                .tx
                .into();
        tx.max_fee_per_gas(gas_fees.max_fee_per_gas)
            .max_priority_fee_per_gas(gas_fees.max_priority_fee_per_gas)
            .into()
    }

    fn decode_simulate_handle_ops_revert(
        &self,
        revert_data: Bytes,
    ) -> Result<ExecutionResult, String> {
        if let Ok(result) = ExecutionResult::decode(&revert_data) {
            //println!("HC decodeSHO OK_result {:?}", result);
            Ok(result)
        } else if let Ok(failed_op) = FailedOp::decode(&revert_data) {
            //println!("HC decodeSHO failedOp {:?}", failed_op.reason);
	    Err(failed_op.reason)
        } else if let Ok(err) = ContractRevertError::decode(&revert_data) {
            println!("HC decodeSHO errReason {:?}", err.reason);
            Err(err.reason)
        } else {
            println!("HC decodeSHO errGeneric");
            Err(String::new())
        }
    }

    async fn get_nonce(&self, address: Address, key: ::ethers::core::types::U256) -> Result<::ethers::core::types::U256, String> {
        let ret = IEntryPoint::get_nonce(self, address, key).await;
        Ok(ret.unwrap())
    }
}

fn get_handle_ops_call<M: Middleware>(
    entry_point: &IEntryPoint<M>,
    mut ops_per_aggregator: Vec<UserOpsPerAggregator>,
    beneficiary: Address,
    gas: U256,
) -> FunctionCall<Arc<M>, M, ()> {
    let call =
        if ops_per_aggregator.len() == 1 && ops_per_aggregator[0].aggregator == Address::zero() {
            //println!("HC get_handle_ops_call will use entry_point.handle_ops");
	    entry_point.handle_ops(ops_per_aggregator.swap_remove(0).user_ops, beneficiary)
        } else {
            //println!("HC get_handle_ops_call will use entry_point.handle_aggregated_ops");
            entry_point.handle_aggregated_ops(ops_per_aggregator, beneficiary)
        };
    call.gas(gas)
}
