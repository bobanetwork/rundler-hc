from dotenv import load_dotenv
import os
from eth_abi import abi as ethabi
from userop_utils import *

load_dotenv()

def test_rainfall_insurance_purchase(aa):
    print("\n  - - - - TestRainfallInsurance(setup) - - - -")

    trigger_rainfall = 50
    city = "London"
    premium = w3.to_wei(0.0001, 'ether')

    calldata =  selector("buyInsurance(uint256,string)") + \
      ethabi.encode(['uint256','string'],[trigger_rainfall, city])


    op = aa.build_op(SA.address, TEST_RAINFALL_INSURANCE.address, premium, calldata, nKey)

    (success, op) = estimateOp(aa, op)
    assert success

    rcpt = aa.sign_submit_op(op, u_key)
    topic = Web3.keccak(text="PolicyCreated(uint256,address,string,uint256,uint256)")
    logs = ParseReceipt(rcpt, topic)
    policy_id = Web3.to_int(hexstr=logs[0][1])

    print("Policy id: ", policy_id, Web3.to_hex(policy_id))
    return policy_id

def test_rainfall_insurance_payout(aa, policy_id):
    global estGas
    print("\n  - - - - TestRainfallInsurance({}) - - - -".format(policy_id))
    payout_call = selector("checkAndPayout(uint256)") + \
        ethabi.encode(['uint256'], [policy_id])

    exCall = selector("execute(address,uint256,bytes)") + \
        ethabi.encode(['address', 'uint256', 'bytes'], [
                      TEST_RAINFALL_INSURANCE.address, 0, payout_call])

    op = aa.build_op(SA.address, TEST_RAINFALL_INSURANCE.address, 0, payout_call, nKey)

    (success, op) = estimateOp(aa, op)
    assert success

    rcpt = aa.sign_submit_op(op, u_key)
    ParseReceipt(rcpt)

    policy = TEST_RAINFALL_INSURANCE.functions.policies(int(os.getenv("POLICY_ID"))).call()
    rainfall = TEST_RAINFALL_INSURANCE.functions.currentRainfall("London").call()
    print("Policy details: ", policy)
    print("Current rainfall in London: ", rainfall)
