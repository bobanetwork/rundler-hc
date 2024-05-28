from web3 import Web3
import time
from random import *
import requests
import json
from web3.middleware import geth_poa_middleware

from jsonrpcclient import request
import requests

import eth_account

deploy_addr = Web3.to_checksum_address(
    "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266")
deploy_key = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

# The following addrs and keys are for local demo purposes. Do not deploy to public networks
u_addr = Web3.to_checksum_address("0x77Fe14A710E33De68855b0eA93Ed8128025328a9")
u_key = "0x541b3e3b20b8bb0e5bae310b2d4db4c8b7912ba09750e6ff161b7e67a26a9bf7"

# HC0 is used within the bundler to insert system error messages
hc0_addr = "0x2A9099A58E0830A4Ab418c2a19710022466F1ce7"
hc0_key = "0x75cd983f0f4714969b152baa258d849473732905e2301467303dacf5a09fdd57"

# HC1 is used by the offchain JSON-RPC endpoint
hc1_addr = Web3.to_checksum_address(
    "0xE073fC0ff8122389F6e693DD94CcDc5AF637448e")
hc1_key = "0x7c0c629efc797f8c5f658919b7efbae01275470d59d03fdeb0fca1e6bd11d7fa"

# This is the EOA account which the bundler will use to submit its batches
bundler_addr = Web3.to_checksum_address(
    "0xB834a876b7234eb5A45C0D5e693566e8842400bB")
bundler_key = "0xf91be07ef5a01328015cae4f2e5aefe3c4577a90abb8e2e913fe071b0e3732ed"

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


def fundAddr(addr):
    if w3.eth.get_balance(addr) == 0:
        print("Funding acct (direct)", addr)
        n = w3.eth.get_transaction_count(deploy_addr)
        v = Web3.to_wei(1.001, 'ether')
        # v += Web3.to_wei(n, 'wei')
        tx = {
            'nonce': n,
            'from': deploy_addr,
            'to': addr,
            'gas': 210000,
            'chainId': HC_CHAIN,
            'value': v
        }
        if w3.eth.gas_price > 1000000:
            tx['gasPrice'] = w3.eth.gas_price
        else:
            tx['gasPrice'] = Web3.to_wei(1, 'gwei')
        signAndSubmit(tx, deploy_key)

def fundAddrEP(addr):
    if EP.functions.deposits(addr).call()[0] < Web3.to_wei(0.005, 'ether'):
        print("Funding acct (depositTo)", addr)
        tx = EP.functions.depositTo(addr).build_transaction({
            'nonce': w3.eth.get_transaction_count(deploy_addr),
            'from': deploy_addr,
            'gas': 210000,
            'chainId': HC_CHAIN,
            'value': Web3.to_wei(0.01, "ether")
        })
        signAndSubmit(tx, deploy_key)
    print("Balances for", addr, Web3.from_wei(w3.eth.get_balance(addr), 'ether'),
          Web3.from_wei(EP.functions.deposits(addr).call()[0], 'ether'))


def setOwner(acct, owner):
    if acct.functions.owner().call() != owner:
        tx = acct.functions.initialize(owner).build_transaction({
            'nonce': w3.eth.get_transaction_count(u_addr),
            'from': u_addr,
            'gas': 210000,
            'chainId': HC_CHAIN,
        })
        signAndSubmit(tx, u_key)


def setSysAcct(sys):
    if HH.functions.systemAccount().call() != sys:
        tx = HH.functions.SetSystemAccount(sys).build_transaction({
            'nonce': w3.eth.get_transaction_count(deploy_addr),
            'from': deploy_addr,
            'gas': 210000,
            'chainId': HC_CHAIN,
        })
        signAndSubmit(tx, deploy_key)


def permitCaller(acct, caller):
    if not acct.functions.PermittedCallers(caller).call():
        print("Permit caller {} on {}".format(caller, acct.address))
        tx = acct.functions.PermitCaller(caller, True).build_transaction({
            'nonce': w3.eth.get_transaction_count(hc1_addr),
            'from': hc1_addr,
            'gas': 210000,
            'chainId': HC_CHAIN,
        })
        signAndSubmit(tx, hc1_key)


def registerUrl(caller, url):
    print("Credit balance=", HH.functions.RegisteredCallers(caller).call()[2])
    # Temporray hack
    if HH.functions.RegisteredCallers(caller).call()[1] != url or HH.functions.RegisteredCallers(caller).call()[2] == 0:
        print("Calling RegisterUrl()")
        tx = HH.functions.RegisterUrl(caller, url).build_transaction({
            'nonce': w3.eth.get_transaction_count(deploy_addr),
            'from': deploy_addr,
            'gas': 210000,
            'chainId': HC_CHAIN,
        })
        signAndSubmit(tx, deploy_key)
        print("Calling AddCredit()")
        tx = HH.functions.AddCredit(caller, 100).build_transaction({
            'nonce': w3.eth.get_transaction_count(deploy_addr),
            'from': deploy_addr,
            'gas': 210000,
            'chainId': HC_CHAIN,
        })
        signAndSubmit(tx, deploy_key)

# -------------------------------------------------------------


print("Setup...")

fundAddr(SA.address)
fundAddrEP(HA.address)
fundAddrEP(BA.address)
fundAddr(bundler_addr)

# FIXME - fix SetOwner() so that these don't need to be funded, only to sign.
fundAddr(u_addr)
fundAddr(hc0_addr)
fundAddr(hc1_addr)

setOwner(HH, deploy_addr)
setSysAcct(BA.address)

setOwner(SA, u_addr)
setOwner(HA, hc1_addr)
setOwner(BA, hc0_addr)

permitCaller(HA, TC.address)
permitCaller(HA, KYC.address)
permitCaller(HA, TFP.address)

# Change IP address as needed.
registerUrl(HA.address, "http://192.168.178.37.:1234/hc")
'''
if not EP.functions.deposits(bundler_addr).call()[1]:
    print("Staking bundler")
    tx = EP.functions.addStake(60).build_transaction({
        'nonce': w3.eth.get_transaction_count(bundler_addr),
        'from': bundler_addr,
        'gas': 210000,
        'chainId': HC_CHAIN,
        'value': Web3.to_wei(0.1, "ether")
    })
    signAndSubmit(tx, bundler_key)
'''
showBalances()
balStart_bnd = w3.eth.get_balance(bundler_addr)
balStart_sa = EP.functions.getDepositInfo(SA.address).call()[0]

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
            print("operation success", opReceipt['success'])
            ParseReceipt(opReceipt)
            timeout = False
            assert (opReceipt['success'])
            break
    if timeout:
        print("*** Previous operation timed out")
        exit(1)
