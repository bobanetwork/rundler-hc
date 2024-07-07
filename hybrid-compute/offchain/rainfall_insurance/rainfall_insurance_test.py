from web3 import Web3
import time
from random import *
import requests

from jsonrpcclient import request
import requests

from eth_abi import abi as ethabi
import eth_account

from userop_utils import *

from dotenv import load_dotenv
import os

load_dotenv()


def test_rainfall_insurance_payout(policy_id):
    global estGas
    print("\n  - - - - TestRainfallInsurance({}) - - - -".format(policy_id))
    payout_call = w3.to_bytes(hexstr="0x"+selector("checkAndPayout(uint256)")) + \
        ethabi.encode(['uint256'], [policy_id])

    exCall = w3.to_bytes(hexstr="0x"+selector("execute(address,uint256,bytes)")) + \
        ethabi.encode(['address', 'uint256', 'bytes'], [
                      TEST_RAINFALL_INSURANCE.address, 0, payout_call])
    p = buildOp(SA, nKey, exCall)

    opHash = EP.functions.getUserOpHash(packOp(p)).call()
    eMsg = eth_account.messages.encode_defunct(opHash)
    sig = w3.eth.account.sign_message(eMsg, private_key=u_key)
    p['signature'] = Web3.to_hex(sig.signature)

    j = [p, EP.address]
    response = requests.post(bundler_rpc, json=request(
        "eth_estimateUserOperationGas", params=j))
    print("estimateGas response", response.json())

    if 'error' in response.json():
        print("*** eth_estimateUserOperationGas failed")
        time.sleep(2)
        if True:
            return
        print("*** Continuing after failure")
        p['preVerificationGas'] = "0xffff"
        p['verificationGasLimit'] = "0xffff"
        p['callGasLimit'] = "0x40000"
    else:
        est_result = response.json()['result']

        p['preVerificationGas'] = Web3.to_hex(Web3.to_int(
            hexstr=est_result['preVerificationGas']) + 0)
        p['verificationGasLimit'] = Web3.to_hex(Web3.to_int(
            hexstr=est_result['verificationGasLimit']) + 0)
        p['callGasLimit'] = Web3.to_hex(Web3.to_int(
            hexstr=est_result['callGasLimit']) + 0)
        estGas = Web3.to_int(hexstr=est_result['preVerificationGas']) + Web3.to_int(
            hexstr=est_result['verificationGasLimit']) + Web3.to_int(hexstr=est_result['callGasLimit'])
        print("estimateGas total =", estGas)

    print("-----")
    submitOp(p)
    print("Pool balance after playing =", Web3.from_wei(
        TC.functions.Pool().call(), 'gwei'))

    policy = TEST_RAINFALL_INSURANCE.functions.policies(int(os.getenv("POLICY_ID"))).call()
    rainfall = TEST_RAINFALL_INSURANCE.functions.currentRainfall("London").call()
    print("Policy details: ", policy)
    print("Current rainfall in London: ", rainfall)
