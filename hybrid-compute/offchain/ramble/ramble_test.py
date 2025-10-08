"""Test the Hybrid Compute word generator + guessing game"""

from eth_abi import abi as ethabi
from web3 import Web3

def test_word_guess(t, n, cheat):
    """Test the Hybrid Compute word generator + guessing game"""
    print(f"\n  - - - - TestWordGuess({n},{cheat}) - - - -")
    test_contract = t.load_contract('TestHybrid')

    game_call = t.selector("wordGuess(string,bool)") + \
        ethabi.encode(['string', 'bool'], ["frog", cheat])

    per_entry = test_contract.functions.EntryCost().call()

    print("Pool balance before playing =", Web3.from_wei(
        test_contract.functions.Pool().call(), 'gwei'))

    op = t.build_op('TestHybrid', n * per_entry, game_call)

    (success, op) = t.estimate_op(op)
    assert success

    rcpt = t.submit_op(op)
    t.parse_receipt(rcpt)

    print("Pool balance after playing =", Web3.from_wei(
        test_contract.functions.Pool().call(), 'gwei'))
