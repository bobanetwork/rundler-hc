from web3 import Web3
import time
from random import *
import requests
import json
from web3.middleware import geth_poa_middleware
import os,re

from jsonrpcclient import request
import requests

import eth_account

from dotenv import load_dotenv, find_dotenv

load_dotenv(find_dotenv())

BUNDLER_ADDR = os.environ['BUNDLER_ADDR']
assert (len(BUNDLER_ADDR) == 42)
bundler_addr = Web3.to_checksum_address(BUNDLER_ADDR)

bundler_rpc = os.environ['BUNDLER_RPC']
assert(len(bundler_rpc) > 0)

node_http = os.environ['NODE_HTTP']
assert(len(node_http) > 0)

HC_CHAIN = int(os.environ['CHAIN_ID'])
assert(HC_CHAIN > 0)

# Owner of the user account used to submit client requests
U_OWNER = os.environ['CLIENT_OWNER']
assert (len(U_OWNER) == 42)
u_addr = Web3.to_checksum_address(U_OWNER)

u_key = os.environ['CLIENT_PRIVKEY']
assert (len(u_key) == 66)

U_ACCT = os.environ['CLIENT_ADDR']
assert (len(U_ACCT) == 42)
u_account = Web3.to_checksum_address(U_ACCT)

# -------------------------------------------------------------

gasFees = dict()
gasFees['estGas'] = 123 # Tracks gas between estimate and receipt; should refactor
gasFees['l2Fees'] = 0   # Cumulative L2 fees
gasFees['l1Fees'] = 0   # Cumulative L1 fees

w3 = Web3(Web3.HTTPProvider(node_http))
assert (w3.is_connected)
w3.middleware_onion.inject(geth_poa_middleware, layer=0)

with open("./contracts.json", "r") as f:
    deployed = json.loads(f.read())

EP = w3.eth.contract(
    address=deployed['EntryPoint']['address'], abi=deployed['EntryPoint']['abi'])
HH = w3.eth.contract(
    address=deployed['HCHelper']['address'], abi=deployed['HCHelper']['abi'])
# This address is unique for each user, who deploys their own wallet account
SA = w3.eth.contract(
    address=u_account, abi=deployed['SimpleAccount']['abi'])
BA = w3.eth.contract(address=deployed['HybridAccount.0']
                     ['address'], abi=deployed['HybridAccount.0']['abi'])
HA = w3.eth.contract(address=deployed['HybridAccount.1']
                     ['address'], abi=deployed['HybridAccount.1']['abi'])
TC = w3.eth.contract(
    address=deployed['TestCounter']['address'], abi=deployed['TestCounter']['abi'])
KYC = w3.eth.contract(
    address=deployed['TestKyc']['address'], abi=deployed['TestKyc']['abi'])
TFP = w3.eth.contract(
    address=deployed['TestTokenPrice']['address'], abi=deployed['TestTokenPrice']['abi'])
#TCAPTCHA = w3.eth.contract(
#    address=deployed['TestCaptcha']['address'], abi=deployed['TestCaptcha']['abi'])
TEST_AUCTION = w3.eth.contract(
    address=deployed['TestAuctionSystem']['address'], abi=deployed['TestAuctionSystem']['abi']
TEST_RAINFALL_INSURANCE = w3.eth.contract(
    address=deployed['TestRainfallInsurance']['address'], abi=deployed['TestRainfallInsurance']['abi']
)

print("EP at", EP.address)

def showBalances():
    print("u  ", EP.functions.getDepositInfo(
        u_addr).call(), w3.eth.get_balance(u_addr))
    print("bnd", EP.functions.getDepositInfo(
        bundler_addr).call(), w3.eth.get_balance(bundler_addr))
    print("SA ", EP.functions.getDepositInfo(
        SA.address).call(), w3.eth.get_balance(SA.address))
    print("BA ", EP.functions.getDepositInfo(
        BA.address).call(), w3.eth.get_balance(BA.address))
    print("HA ", EP.functions.getDepositInfo(
        HA.address).call(), w3.eth.get_balance(HA.address))
    print("TC ", EP.functions.getDepositInfo(
        TC.address).call(), w3.eth.get_balance(TC.address))
    print("TFP", EP.functions.getDepositInfo(
        TFP.address).call(), w3.eth.get_balance(TFP.address))
    print("AUCTION_SYSTEM", EP.functions.getDepositInfo(TEST_AUCTION.address).call(), w3.eth.get_balance(TEST_AUCTION.address))
#    print("TCAPTCHA", EP.functions.getDepositInfo(
#        TCAPTCHA.address).call(), w3.eth.get_balance(TCAPTCHA.address))
    print("TEST_RAINFALL_INSURANCE", EP.functions.getDepositInfo(
        TEST_RAINFALL_INSURANCE.address).call(), w3.eth.get_balance(TEST_RAINFALL_INSURANCE.address))


# -------------------------------------------------------------


def selector(name):
    nameHash = Web3.to_hex(Web3.keccak(text=name))
    return nameHash[2:10]


def signAndSubmit(tx, key):
    signed_txn = w3.eth.account.sign_transaction(tx, key)
    ret = w3.eth.send_raw_transaction(signed_txn.rawTransaction)
    rcpt = w3.eth.wait_for_transaction_receipt(ret)
    assert (rcpt.status == 1)
    return rcpt


def buildAndSubmit(f, addr, key):
    tx = f.build_transaction({
        'nonce': w3.eth.get_transaction_count(addr),
        'from': addr,
        'gas': 210000,
        'chainId': HC_CHAIN,
    })
    return signAndSubmit(tx, key)


def buildOp(A, nKey, payload):
    sender_nonce = EP.functions.getNonce(A.address, nKey).call()

    # Try to avoid stuck / dropped transactions
    tip = max(w3.eth.max_priority_fee, 2500000)
    baseFee = w3.eth.gas_price - w3.eth.max_priority_fee
    assert(baseFee > 0)
    fee = max(w3.eth.gas_price, baseFee + tip)
    print ("Using gas prices", fee, tip, "detected", w3.eth.gas_price, w3.eth.max_priority_fee)

    p = {
        'sender': A.address,
        'nonce': Web3.to_hex(sender_nonce),  # A.functions.getNonce().call()),
        'initCode': '0x',
        'callData': Web3.to_hex(payload),
        'callGasLimit': "0x0",
        'verificationGasLimit': Web3.to_hex(0),
        'preVerificationGas': "0x0",
        'maxFeePerGas': Web3.to_hex(fee),
        'maxPriorityFeePerGas': Web3.to_hex(tip),
        'paymasterAndData': '0x',
        # Dummy signature, per Alchemy AA documentation
        # A future update may require a valid signature on gas estimation ops. This should be safe because the gas
        # limits in the signed request are set to zero, therefore it would be rejected if a third party attempted to
        # submit it as a real transaction.
        'signature': '0xfffffffffffffffffffffffffffffff0000000000000000000000000000000007aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1c'
    }
    print(p)
    return p


def packOp(op):
    ret = (
        op['sender'],
        Web3.to_int(hexstr=op['nonce']),
        op['initCode'],
        Web3.to_bytes(hexstr=op['callData']),
        Web3.to_int(hexstr=op['callGasLimit']),
        Web3.to_int(hexstr=op['verificationGasLimit']),
        Web3.to_int(hexstr=op['preVerificationGas']),
        Web3.to_int(hexstr=op['maxFeePerGas']),
        Web3.to_int(hexstr=op['maxPriorityFeePerGas']),
        op['paymasterAndData'],
        Web3.to_bytes(hexstr=op['signature'])
    )
    return ret

# -------------------------------------------------------------

def estimateOp(p):
    global gasFees

    est_params = [p, EP.address]
    print("estimation params {}".format(est_params))

    response = requests.post(
        bundler_rpc, json=request("eth_estimateUserOperationGas", params=est_params))
    print("estimateGas response", response.json())

    if 'error' in response.json():
        print("*** eth_estimateUserOperationGas failed")
        time.sleep(2)
        if True:
            return p, 0
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

        gasFees['estGas'] = Web3.to_int(hexstr=est_result['preVerificationGas']) + Web3.to_int(
            hexstr=est_result['verificationGasLimit']) + Web3.to_int(hexstr=est_result['callGasLimit'])
        print("estimateGas total =", gasFees['estGas'])
    return p, gasFees['estGas']

# ===============================================

# Generates an AA-style nonce (each key has its own associated sequence count)
nKey = int(1200 + (w3.eth.get_transaction_count(u_addr) % 7))
# nKey = 0
#print("nKey", nKey)

def ParseReceipt(opReceipt):
    global gasFees
    txRcpt = opReceipt['receipt']

    n = 0
    for i in txRcpt['logs']:
        print("log", n, i['topics'][0], i['data'])
        n += 1
    print("Total tx gas stats:",
        "gasUsed", Web3.to_int(hexstr=txRcpt['gasUsed']),
	"effectiveGasPrice", Web3.to_int(hexstr=txRcpt['effectiveGasPrice']),
	"l1GasUsed", Web3.to_int(hexstr=txRcpt['l1GasUsed']),
	"l1Fee", Web3.to_int(hexstr=txRcpt['l1Fee']))
    opGas = Web3.to_int(hexstr=opReceipt['actualGasUsed'])
    print("opReceipt gas used", opGas, "unused", gasFees['estGas'] - opGas)

    egPrice = Web3.to_int(hexstr=txRcpt['effectiveGasPrice'])
    gasFees['l2Fees'] += Web3.to_int(hexstr=txRcpt['gasUsed']) * egPrice
    gasFees['l1Fees'] += Web3.to_int(hexstr=txRcpt['l1Fee'])
    # exit(0)


def submitOp(p):
    opHash = EP.functions.getUserOpHash(packOp(p)).call()
    eMsg = eth_account.messages.encode_defunct(opHash)
    sig = w3.eth.account.sign_message(eMsg, private_key=u_key)
    p['signature'] = Web3.to_hex(sig.signature)
    while True:
        response = requests.post(bundler_rpc, json=request(
            "eth_sendUserOperation", params=[p, EP.address]))
        if 'result' in response.json():
            break
        elif 'error' in response.json():
            emsg = response.json()['error']['message']
            if not re.search(r'message: block 0x.{64} not found', emsg): # Workaround for sending debug_traceCall to unsynced node
                break
        print("*** Retrying eth_sendUserOperation")
        time.sleep(5)

    print("sendOperation response", response.json())
    if 'error' in response.json():
        print("*** eth_sendUserOperation failed")
        exit(1)

    opHash = {}
    opHash['hash'] = response.json()['result']
    timeout = True
    for i in range(100):
        print("Waiting for receipt...")
        time.sleep(10)
        opReceipt = requests.post(bundler_rpc, json=request(
            "eth_getUserOperationReceipt", params=opHash))
        opReceipt = opReceipt.json()['result']
        if opReceipt is not None:
            # print("opReceipt", opReceipt)
            assert (opReceipt['receipt']['status'] == "0x1")
            print("operation success", opReceipt['success'],
                  "txHash=", opReceipt['receipt']['transactionHash'])
            ParseReceipt(opReceipt)
            timeout = False
            assert (opReceipt['success'])
            break
    if timeout:
        print("*** Previous operation timed out")
        exit(1)
