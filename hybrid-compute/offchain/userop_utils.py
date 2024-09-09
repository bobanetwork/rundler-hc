from web3 import Web3
import time
from random import *
import requests
import json
import os
import re

from jsonrpcclient import request
import requests

import eth_account

from dotenv import load_dotenv, find_dotenv

load_dotenv(find_dotenv())

import sys
sys.path.append(".") # Workaround until aa_utils etc. can be packaged properly
from aa_utils import *

EP_ADDR = os.environ['ENTRY_POINTS']
assert (len(EP_ADDR) == 42)
ep_addr = Web3.to_checksum_address(EP_ADDR)

BUNDLER_ADDR = os.environ['BUNDLER_ADDR']
assert (len(BUNDLER_ADDR) == 42)
bundler_addr = Web3.to_checksum_address(BUNDLER_ADDR)

bundler_rpc = os.environ['BUNDLER_RPC']
assert (len(bundler_rpc) > 0)

node_http = os.environ['NODE_HTTP']
assert (len(node_http) > 0)

HC_CHAIN = int(os.environ['CHAIN_ID'])
assert (HC_CHAIN > 0)

# Owner of the user account used to submit client requests
U_OWNER = os.environ['CLIENT_OWNER']
assert (len(U_OWNER) == 42)
u_addr = Web3.to_checksum_address(U_OWNER)

u_key = os.environ['CLIENT_PRIVKEY']
assert (len(u_key) == 66)

U_ACCT = os.environ['CLIENT_ADDR']
assert (len(U_ACCT) == 42)
u_account = Web3.to_checksum_address(U_ACCT)

TEST_COUNTER = os.environ['TEST_COUNTER']
assert (len(TEST_COUNTER) == 42)
test_counter = Web3.to_checksum_address(TEST_COUNTER)

# -------------------------------------------------------------

gasFees = dict()
# Tracks gas between estimate and receipt; should refactor
gasFees['estGas'] = 123
gasFees['l2Fees'] = 0   # Cumulative L2 fees
gasFees['l1Fees'] = 0   # Cumulative L1 fees

w3 = Web3(Web3.HTTPProvider(node_http, request_kwargs={'timeout': 900}))
assert (w3.is_connected)

l2_util = eth_utils(w3)

with open("./contracts.json", "r") as f:
    deployed = json.loads(f.read())

EP = w3.eth.contract(
    address=ep_addr, abi=deployed['EntryPoint']['abi'])
HH = w3.eth.contract(
    address=deployed['HCHelper']['address'], abi=deployed['HCHelper']['abi'])
# This address is unique for each user, who deploys their own wallet account
SA = w3.eth.contract(
    address=u_account, abi=deployed['SimpleAccount']['abi'])
HA = w3.eth.contract(address=deployed['HybridAccount']
                     ['address'], abi=deployed['HybridAccount']['abi'])
TC = w3.eth.contract(
    address=test_counter, abi=deployed['TestCounter']['abi'])
#KYC = w3.eth.contract(
#    address=deployed['TestKyc']['address'], abi=deployed['TestKyc']['abi'])
#TFP = w3.eth.contract(
#    address=deployed['TestTokenPrice']['address'], abi=deployed['TestTokenPrice']['abi'])
#TCAPTCHA = w3.eth.contract(
#    address=deployed['TestCaptcha']['address'], abi=deployed['TestCaptcha']['abi'])
TEST_AUCTION = w3.eth.contract(
    address=deployed['TestAuctionSystem']['address'], abi=deployed['TestAuctionSystem']['abi'])
TEST_SPORTS_BETTING = w3.eth.contract(
    address=deployed['TestSportsBetting']['address'], abi=deployed['TestSportsBetting']['abi'])
TEST_RAINFALL_INSURANCE = w3.eth.contract(
    address=deployed['TestRainfallInsurance']['address'], abi=deployed['TestRainfallInsurance']['abi'])

print("EP at", EP.address)


def showBalances():
    print("u  ", EP.functions.getDepositInfo(
        u_addr).call(), w3.eth.get_balance(u_addr))
    print("bnd", EP.functions.getDepositInfo(
        bundler_addr).call(), w3.eth.get_balance(bundler_addr))
    print("SA ", EP.functions.getDepositInfo(
        SA.address).call(), w3.eth.get_balance(SA.address))
    print("HA ", EP.functions.getDepositInfo(
        HA.address).call(), w3.eth.get_balance(HA.address))
    print("TC ", EP.functions.getDepositInfo(
        TC.address).call(), w3.eth.get_balance(TC.address))
#    print("TFP", EP.functions.getDepositInfo(
#        TFP.address).call(), w3.eth.get_balance(TFP.address))
    print("AUCTION_SYSTEM", EP.functions.getDepositInfo(TEST_AUCTION.address).call(), w3.eth.get_balance(TEST_AUCTION.address))
#    print("TCAPTCHA", EP.functions.getDepositInfo(
#        TCAPTCHA.address).call(), w3.eth.get_balance(TCAPTCHA.address))
    print("TEST_RAINFALL_INSURANCE", EP.functions.getDepositInfo(
        TEST_RAINFALL_INSURANCE.address).call(), w3.eth.get_balance(TEST_RAINFALL_INSURANCE.address))
    print("SPORTS BETTING", EP.functions.getDepositInfo(
        TEST_SPORTS_BETTING.address).call(), w3.eth.get_balance(TEST_SPORTS_BETTING.address))

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
# print("nKey", nKey)

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
