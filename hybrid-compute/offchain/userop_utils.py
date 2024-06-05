from web3 import Web3
import time
from random import *
import requests
import json
from web3.middleware import geth_poa_middleware

from jsonrpcclient import request
import requests

import eth_account

# The following addrs and keys are for local demo purposes. Do not deploy to public networks
u_addr = Web3.to_checksum_address("0x77Fe14A710E33De68855b0eA93Ed8128025328a9")
u_key = "0x541b3e3b20b8bb0e5bae310b2d4db4c8b7912ba09750e6ff161b7e67a26a9bf7"

# HC0 is used within the bundler to insert system error messages
hc0_addr = "0x2A9099A58E0830A4Ab418c2a19710022466F1ce7"

# HC1 is used by the offchain JSON-RPC endpoint
hc1_addr = Web3.to_checksum_address(
    "0xE073fC0ff8122389F6e693DD94CcDc5AF637448e")

# This is the EOA account which the bundler will use to submit its batches
bundler_addr = Web3.to_checksum_address(
    "0xB834a876b7234eb5A45C0D5e693566e8842400bB")

bundler_rpc = "http://127.0.0.1:3300"

# -------------------------------------------------------------

w3 = Web3(Web3.HTTPProvider("http://127.0.0.1:9545"))
assert (w3.is_connected)
w3.middleware_onion.inject(geth_poa_middleware, layer=0)
HC_CHAIN = 901

with open("./contracts.json", "r") as f:
    deployed = json.loads(f.read())

EP = w3.eth.contract(
    address=deployed['EntryPoint']['address'], abi=deployed['EntryPoint']['abi'])
HH = w3.eth.contract(
    address=deployed['HCHelper']['address'], abi=deployed['HCHelper']['abi'])
SA = w3.eth.contract(
    address=deployed['SimpleAccount']['address'], abi=deployed['SimpleAccount']['abi'])
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
TCAPTCHA = w3.eth.contract(
    address=deployed['TestCaptcha']['address'], abi=deployed['TestCaptcha']['abi'])


print("EP at", EP.address)


def showBalances():
    print("u  ", EP.functions.getDepositInfo(
        u_addr).call(), w3.eth.get_balance(u_addr))
    print("hc0", EP.functions.getDepositInfo(
        hc0_addr).call(), w3.eth.get_balance(hc0_addr))
    print("hc1", EP.functions.getDepositInfo(
        hc1_addr).call(), w3.eth.get_balance(hc1_addr))
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
    print("TCAPTCHA", EP.functions.getDepositInfo(
        TCAPTCHA.address).call(), w3.eth.get_balance(TCAPTCHA.address))


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

    p = {
        'sender': A.address,
        'nonce': Web3.to_hex(sender_nonce),  # A.functions.getNonce().call()),
        'initCode': '0x',
        'callData': Web3.to_hex(payload),
        'callGasLimit': "0x0",
        'verificationGasLimit': Web3.to_hex(0),
        'preVerificationGas': "0x0",
        'maxFeePerGas': Web3.to_hex(w3.eth.gas_price),
        'maxPriorityFeePerGas': Web3.to_hex(w3.eth.max_priority_fee),
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


showBalances()
balStart_bnd = w3.eth.get_balance(bundler_addr)
balStart_sa = EP.functions.getDepositInfo(
    SA.address).call()[0] + w3.eth.get_balance(SA.address)

print("TestCount(pre)=", TC.functions.counters(SA.address).call())
print("TestFetchPrice(pre)=", TFP.functions.counters(0).call())

# ===============================================
print("\n------\n")

# Generates an AA-style nonce (each key has its own associated sequence count)
nKey = int(1000 + (w3.eth.get_transaction_count(u_addr) % 7))
# nKey = 0
print("nKey", nKey)
l2Fees = 0
l1Fees = 0
egPrice = 0
estGas = 0


def ParseReceipt(opReceipt):
    global l1Fees, l2Fees, egPrice
    txRcpt = opReceipt['receipt']

    n = 0
    for i in txRcpt['logs']:
        print("log", n, i['topics'][0], i['data'])
        n += 1
    print("Total tx gas stats:", Web3.to_int(
        hexstr=txRcpt['gasUsed']), txRcpt['l1GasUsed'], txRcpt['l1Fee'])
    opGas = Web3.to_int(hexstr=opReceipt['actualGasUsed'])
    print("opReceipt gas used", opGas, "unused", estGas - opGas)

    egPrice = Web3.to_int(hexstr=txRcpt['effectiveGasPrice'])
    l2Fees += Web3.to_int(hexstr=txRcpt['gasUsed']) * egPrice
    l1Fees += Web3.to_int(hexstr=txRcpt['l1Fee'])
    # exit(0)


def submitOp(p):
    opHash = EP.functions.getUserOpHash(packOp(p)).call()
    eMsg = eth_account.messages.encode_defunct(opHash)
    sig = w3.eth.account.sign_message(eMsg, private_key=u_key)
    p['signature'] = Web3.to_hex(sig.signature)

    response = requests.post(bundler_rpc, json=request(
        "eth_sendUserOperation", params=[p, EP.address]))
    print("sendOperation response", response.json())

    opHash = {}
    opHash['hash'] = response.json()['result']
    timeout = True
    for i in range(10):
        print("Waiting for receipt...")
        time.sleep(1)
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
