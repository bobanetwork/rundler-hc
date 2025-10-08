"""Test the Hybrid Compute sports betting example"""
import time
from eth_abi import abi as ethabi

def test_sports_betting(t):
    """Test the Hybrid Compute sports betting example"""
    print("\n  - - - - SportBetting() - - - -")

    game_id = 456
    create_bet(t, game_id)
    place_bet(t, game_id)
    settle_bet(t, game_id)
    test_contract = t.load_contract('TestSportsBetting')

    bets = test_contract.functions.bets(game_id, 0).call()
    game = test_contract.functions.games(game_id).call()
    score = test_contract.functions.gameScores(game_id).call()
    print("Bets: ", bets)
    print("Game: ", game)
    print("Score: ", score)
    print("Test Sports Betting end")

def create_bet(t, game_id):
    """Create a game to accept bets"""
    print("--------------------Create Bet--------------------")
    create_call = t.selector("createGame(uint256)") + ethabi.encode(['uint256'], [game_id])

    op = t.build_op('TestSportsBetting', 0, create_call)

    (success, op) = t.estimate_op(op)
    assert success

    rcpt = t.submit_op(op)
    t.parse_receipt(rcpt)

    print("Create Bet end")

def place_bet(t, game_id):
    """Place a bet"""
    print("--------------------Place Bet--------------------")
    outcome = 1
    place_calldata = t.selector("placeBet(uint256,uint256)") + ethabi.encode(['uint256', 'uint256'],
                                                                            [game_id, outcome])
    amount_to_bet = 2

    op = t.build_op('TestSportsBetting', amount_to_bet, place_calldata)

    (success, op) = t.estimate_op(op)
    assert success

    rcpt = t.submit_op(op)
    t.parse_receipt(rcpt)

    print("Place Bet end")

def settle_bet(t, game_id):
    """Settle bets"""
    print("--------------------Settle Bet--------------------")
    settle_calldata = t.selector("settleBet(uint256)") + ethabi.encode(['uint256'], [game_id])

    op = t.build_op('TestSportsBetting', 0, settle_calldata)
    time.sleep(5)
    (success, op) = t.estimate_op(op)
    assert success

    rcpt = t.submit_op(op)
    t.parse_receipt(rcpt)

    print("Settle Bet end")
