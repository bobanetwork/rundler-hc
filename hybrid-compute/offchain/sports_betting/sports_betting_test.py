from web3 import Web3
import time
from random import *
import requests

from jsonrpcclient import request
import requests

from eth_abi import abi as ethabi
import eth_account

from userop_utils import *


def TestSportsBetting():
    print("\n  - - - - SportBetting() - - - -")
    print("SA ADDRESS {}".format(SA.address))

    game_id = 456
    create_bet(game_id)
    place_bet(game_id)
    settle_bet(game_id)
    bets = TEST_SPORTS_BETTING.functions.bets(game_id, 0).call()
    game = TEST_SPORTS_BETTING.functions.games(game_id).call()
    score = TEST_SPORTS_BETTING.functions.gameScores(game_id).call()
    print("Bets: ", bets)
    print("Game: ", game)
    print("Score: ", score)
    print("Test Sports Betting end")


def create_bet(game_id):
    print("--------------------Create Bet--------------------")
    create_call = Web3.to_bytes(
        hexstr="0x"+selector("createGame(uint256)")) + ethabi.encode(['uint256'], [game_id])

    exCall = Web3.to_bytes(hexstr="0x"+selector("execute(address,uint256,bytes)")) + ethabi.encode(
        ['address', 'uint256', 'bytes'], [TEST_SPORTS_BETTING.address, 0, create_call])

    p = buildOp(SA, nKey, exCall)

    opHash = EP.functions.getUserOpHash(packOp(p)).call()
    eMsg = eth_account.messages.encode_defunct(opHash)
    sig = w3.eth.account.sign_message(eMsg, private_key=u_key)
    p['signature'] = Web3.to_hex(sig.signature)

    p, est = estimateOp(p)
    if est == 0:  # Estimation failed.
        return

    opHash = EP.functions.getUserOpHash(packOp(p)).call()
    eMsg = eth_account.messages.encode_defunct(opHash)
    sig = w3.eth.account.sign_message(eMsg, private_key=u_key)
    p['signature'] = Web3.to_hex(sig.signature)

    print("-----")
    submitOp(p)
    print("Create Bet end")


def place_bet(game_id):
    print("--------------------Place Bet--------------------")
    outcome = 1
    place_bet = Web3.to_bytes(
        hexstr="0x"+selector("placeBet(uint256,uint256)")) + ethabi.encode(['uint256', 'uint256'],
                                                                            [game_id, outcome])

    amount_to_bet = 2
    exCall = Web3.to_bytes(hexstr="0x"+selector("execute(address,uint256,bytes)")) + ethabi.encode(
        ['address', 'uint256', 'bytes'], [TEST_SPORTS_BETTING.address, amount_to_bet, place_bet])

    p = buildOp(SA, nKey, exCall)

    opHash = EP.functions.getUserOpHash(packOp(p)).call()
    eMsg = eth_account.messages.encode_defunct(opHash)
    sig = w3.eth.account.sign_message(eMsg, private_key=u_key)
    p['signature'] = Web3.to_hex(sig.signature)

    p, est = estimateOp(p)
    if est == 0:  # Estimation failed.
        return

    opHash = EP.functions.getUserOpHash(packOp(p)).call()
    eMsg = eth_account.messages.encode_defunct(opHash)
    sig = w3.eth.account.sign_message(eMsg, private_key=u_key)
    p['signature'] = Web3.to_hex(sig.signature)

    print("-----")
    submitOp(p)
    print("Place Bet end")


def settle_bet(game_id):
    print("--------------------Settle Bet--------------------")
    settle_bet = Web3.to_bytes(
        hexstr="0x"+selector("settleBet(uint256)")) + ethabi.encode(['uint256'], [game_id])

    exCall = Web3.to_bytes(hexstr="0x"+selector("execute(address,uint256,bytes)")) + ethabi.encode(
        ['address', 'uint256', 'bytes'], [TEST_SPORTS_BETTING.address, 0, settle_bet])

    p = buildOp(SA, nKey, exCall)

    opHash = EP.functions.getUserOpHash(packOp(p)).call()
    eMsg = eth_account.messages.encode_defunct(opHash)
    sig = w3.eth.account.sign_message(eMsg, private_key=u_key)
    p['signature'] = Web3.to_hex(sig.signature)

    p, est = estimateOp(p)
    if est == 0:  # Estimation failed.
        return

    opHash = EP.functions.getUserOpHash(packOp(p)).call()
    eMsg = eth_account.messages.encode_defunct(opHash)
    sig = w3.eth.account.sign_message(eMsg, private_key=u_key)
    p['signature'] = Web3.to_hex(sig.signature)

    print("-----")
    submitOp(p)
    print("Settle Bet end")
