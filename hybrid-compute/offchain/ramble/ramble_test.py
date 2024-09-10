from eth_abi import abi as ethabi
from userop_utils import *

def TestWordGuess(aa, n, cheat):
    print(f"\n  - - - - TestWordGuess({n},{cheat}) - - - -")

    game_call = selector("wordGuess(string,bool)") + \
        ethabi.encode(['string', 'bool'], ["frog", cheat])

    per_entry = TC.functions.EntryCost().call()
    print("Pool balance before playing =", Web3.from_wei(
        TC.functions.Pool().call(), 'gwei'))

    op = aa.build_op(SA.address, TC.address, n * per_entry, game_call, nKey)

    (success, op) = estimateOp(aa, op)
    assert success

    print("-----")
    rcpt = aa.sign_submit_op(op, u_key)
    ParseReceipt(rcpt)

    print("Pool balance after playing =", Web3.from_wei(
        TC.functions.Pool().call(), 'gwei'))
