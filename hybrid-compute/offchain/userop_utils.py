from random import *
import json
import os
import sys
from dotenv import load_dotenv, find_dotenv

from web3 import Web3
import eth_account

load_dotenv(find_dotenv())

sys.path.append(".") # Workaround until aa_utils etc. can be packaged properly
from aa_utils import *

EP_ADDR = os.environ['ENTRY_POINTS']
assert len(EP_ADDR) == 42
ep_addr = Web3.to_checksum_address(EP_ADDR)

BUNDLER_ADDR = os.environ['BUNDLER_ADDR']
assert len(BUNDLER_ADDR) == 42
bundler_addr = Web3.to_checksum_address(BUNDLER_ADDR)

bundler_rpc = os.environ['BUNDLER_RPC']
assert len(bundler_rpc) > 0

node_http = os.environ['NODE_HTTP']
assert len(node_http) > 0

HC_CHAIN = int(os.environ['CHAIN_ID'])
assert HC_CHAIN > 0

# Owner of the user account used to submit client requests
U_OWNER = os.environ['CLIENT_OWNER']
assert len(U_OWNER) == 42
u_addr = Web3.to_checksum_address(U_OWNER)

u_key = os.environ['CLIENT_PRIVKEY']
assert len(u_key) == 66

U_ACCT = os.environ['CLIENT_ADDR']
assert len(U_ACCT) == 42
u_account = Web3.to_checksum_address(U_ACCT)

PM_ADDR = os.environ['SIMPLE_PM']
if PM_ADDR:
  assert PM_ADDR == Web3.to_checksum_address(PM_ADDR)

# -------------------------------------------------------------

gasFees = {}
# Tracks gas between estimate and receipt; should refactor
gasFees['estGas'] = 0
gasFees['l2Fees'] = 0   # Cumulative L2 fees
gasFees['l1Fees'] = 0   # Cumulative L1 fees

w3 = Web3(Web3.HTTPProvider(node_http, request_kwargs={'timeout': 900}))
assert (w3.is_connected)

l2_util = eth_utils(w3)

with open("./contracts.json", "r", encoding="ascii") as f:
    deployed = json.loads(f.read())

EP = w3.eth.contract(
    address=ep_addr, abi=deployed['EntryPoint']['abi'])
HH = w3.eth.contract(
    address=os.environ['HC_HELPER_ADDR'], abi=deployed['HCHelper']['abi'])
# This address is unique for each user, who deploys their own wallet account
#SA = w3.eth.contract(
#    address=u_account, abi=deployed['SimpleAccount']['abi'])

HA = w3.eth.contract(address=os.environ['OC_HYBRID_ACCOUNT'],
                     abi=deployed['HybridAccount']['abi'])
TC = w3.eth.contract(
    address=os.environ['TEST_HYBRID'], abi=deployed['TestHybrid']['abi'])
KYC = w3.eth.contract(
    address=os.environ['TEST_KYC'], abi=deployed['TestKyc']['abi'])
TFP = w3.eth.contract(
    address=os.environ['TEST_TOKEN_PRICE'], abi=deployed['TestTokenPrice']['abi'])
#TCAPTCHA = w3.eth.contract(
#    address=deployed['TestCaptcha']['address'], abi=deployed['TestCaptcha']['abi'])
TEST_AUCTION = w3.eth.contract(
    address=os.environ['TEST_AUCTION'], abi=deployed['TestAuctionSystem']['abi'])
TEST_SPORTS_BETTING = w3.eth.contract(
    address=os.environ['TEST_SPORTS_BETTING'], abi=deployed['TestSportsBetting']['abi'])
TEST_RAINFALL_INSURANCE = w3.eth.contract(
    address=os.environ['TEST_RAINFALL_INSURANCE'], abi=deployed['TestRainfallInsurance']['abi'])

print("EP at", EP.address)

boba_token = os.environ['BOBA_TOKEN']

def boba_balance(addr):
    """Returns the Boba token balance of an address"""
    bal_calldata = selector("balanceOf(address)") + ethabi.encode(['address'], [addr])
    bal = w3.eth.call({'to':boba_token, 'data':bal_calldata})
    return Web3.to_int(bal)

def show_balances():
    print("CLIENT_ADDR", EP.functions.getDepositInfo(
        u_account).call(), w3.eth.get_balance(u_account))
    print("BUNDLER_ADDR", EP.functions.getDepositInfo(
        bundler_addr).call(), w3.eth.get_balance(bundler_addr))
    print("OC_HYBRID_ACCOUNT ", EP.functions.getDepositInfo(
        HA.address).call(), w3.eth.get_balance(HA.address))
    print("Helper BOBA token:", boba_balance(HH.address))
    print("HybridAcct BOBA token:", boba_balance(HA.address))
    print("Client BOBA token:", boba_balance(u_account))

# -------------------------------------------------------------

def estimateOp(aa, p):
    global gasFees

    (success, p) = aa.estimate_op_gas(p)
    if not success:
        return False, p

    gasFees['estGas'] = Web3.to_int(hexstr=p['preVerificationGas']) \
        + Web3.to_int(hexstr=p['verificationGasLimit']) \
        + Web3.to_int(hexstr=p['callGasLimit'])
    print("estimateGas total =", gasFees['estGas'])
    print("-----")
    return True, p

# ===============================================

# Generates an AA-style nonce (each key has its own associated sequence count)
nKey = int(1200 + (w3.eth.get_transaction_count(u_addr) % 7))
# nKey = 0
# print("nKey", nKey)

def ParseReceipt(op_receipt, log_topic=None):
    """Parses an operation receipt to extract gas information. Can optionally look
       for one specified log topic and return a matching entry. Sufficient for the
       current examples but not intended as a general solution."""
    global gasFees
    tx_rcpt = op_receipt['receipt']
    log_ret = None

    n = 0
    for i in tx_rcpt['logs']:
        print("log", n, i['topics'][0], i['data'])
        if log_topic and Web3.to_hex(log_topic) == i['topics'][0]:
            log_ret = (i['topics'], i['data'])
        n += 1
    if 'l1GasUsed' not in tx_rcpt:
        tx_rcpt['l1GasUsed'] = "0x0"
    if 'l1Fee' not in tx_rcpt:
        tx_rcpt['l1Fee'] = "0x0"

    print("Total tx gas stats:",
          "gasUsed", Web3.to_int(hexstr=tx_rcpt['gasUsed']),
          "effectiveGasPrice", Web3.to_int(hexstr=tx_rcpt['effectiveGasPrice']),
          "l1GasUsed", Web3.to_int(hexstr=tx_rcpt['l1GasUsed']),
          "l1Fee", Web3.to_int(hexstr=tx_rcpt['l1Fee']))
    op_gas = Web3.to_int(hexstr=op_receipt['actualGasUsed'])
    print("op_receipt gas used", op_gas, "unused", gasFees['estGas'] - op_gas)

    eg_price = Web3.to_int(hexstr=tx_rcpt['effectiveGasPrice'])
    gasFees['l2Fees'] += Web3.to_int(hexstr=tx_rcpt['gasUsed']) * eg_price
    gasFees['l1Fees'] += Web3.to_int(hexstr=tx_rcpt['l1Fee'])

    return log_ret
