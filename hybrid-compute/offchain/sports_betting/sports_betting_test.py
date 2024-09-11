from eth_abi import abi as ethabi
from userop_utils import *
import time
def TestSportsBetting(aa):
    print("\n  - - - - SportBetting() - - - -")
    print("SA ADDRESS {}".format(SA.address))

    game_id = 456
    create_bet(aa, game_id)
    place_bet(aa, game_id)
    settle_bet(aa, game_id)
    bets = TEST_SPORTS_BETTING.functions.bets(game_id, 0).call()
    game = TEST_SPORTS_BETTING.functions.games(game_id).call()
    score = TEST_SPORTS_BETTING.functions.gameScores(game_id).call()
    print("Bets: ", bets)
    print("Game: ", game)
    print("Score: ", score)
    print("Test Sports Betting end")

def create_bet(aa, game_id):
    print("--------------------Create Bet--------------------")
    create_call = selector("createGame(uint256)") + ethabi.encode(['uint256'], [game_id])

    op = aa.build_op(SA.address, TEST_SPORTS_BETTING.address, 0, create_call, nKey)

    (success, op) = estimateOp(aa, op)
    assert success

    rcpt = aa.sign_submit_op(op, u_key)
    ParseReceipt(rcpt)

    print("Create Bet end")

def place_bet(aa, game_id):
    print("--------------------Place Bet--------------------")
    outcome = 1
    place_bet = selector("placeBet(uint256,uint256)") + ethabi.encode(['uint256', 'uint256'],
                                                                            [game_id, outcome])
    amount_to_bet = 2

    op = aa.build_op(SA.address, TEST_SPORTS_BETTING.address, amount_to_bet, place_bet, nKey)

    (success, op) = estimateOp(aa, op)
    assert success

    rcpt = aa.sign_submit_op(op, u_key)
    ParseReceipt(rcpt)

    print("Place Bet end")

def settle_bet(aa, game_id):
    print("--------------------Settle Bet--------------------")
    settle_bet = selector("settleBet(uint256)") + ethabi.encode(['uint256'], [game_id])

    op = aa.build_op(SA.address, TEST_SPORTS_BETTING.address, 0, settle_bet, nKey)
    time.sleep(5)
    (success, op) = estimateOp(aa, op)
    assert success

    rcpt = aa.sign_submit_op(op, u_key)
    ParseReceipt(rcpt)

    print("Settle Bet end")
