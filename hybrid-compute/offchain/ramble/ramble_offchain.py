"""Offchain handler for the Hybrid Compute word generator + guessing game"""
import re
import random
from web3 import Web3
from eth_abi import abi as ethabi
from hybrid_compute_sdk.server import HybridComputeSDK

def get_handlers():
    """Return the method signatures and the associated handlers"""
    print("--> ramble(uint256,bool)")
    return [("ramble(uint256,bool)", offchain_ramble)]

wordlist = []
def load_words():
    """Loads a list of dictionary words, assumes a standard file path"""
    with open("/usr/share/dict/words", "r", encoding="utf-8") as f:
        p = re.compile('^[a-z]{4}$')
        for line in f.readlines():
            line = line.strip()
            if p.match(line) and line != "frog": # Reserved for "cheat" mode
                wordlist.append(line)
    return wordlist

def offchain_ramble(ver, sk, src_addr, src_nonce, oo_nonce, payload, *args):
    """Generates a random list of words, cheating if requested to do so"""
    print(f"  -> offchain_ramble handler called with subkey={sk} "
        f"src_addr={src_addr} src_nonce={src_nonce} oo_nonce={oo_nonce} "
        f"payload={payload} extra_args={args}"
    )
    err_code = 1
    resp = Web3.to_bytes(text="unknown error")
    assert ver == "0.3"
    sdk = HybridComputeSDK()

    try:
        req = sdk.parse_req(sk, src_addr, src_nonce, oo_nonce, payload)
        (n, cheat) = ethabi.decode(['uint256', 'bool'], req['reqBytes'])
        words = []

        if 1 <= n < 1000:
            for _i in range(n):
                r = random.randint(0, len(wordlist)-1)
                words.append(wordlist[r])

            if cheat:
                pos = random.randint(0, len(words)-1)
                print("Cheat at position", pos)
                words[pos] = "frog"

            resp = ethabi.encode(['string[]'], [words])
            err_code = 0
        else:
            print("Invalid length", n)
            resp = Web3.to_bytes(text="invalid string length")
    except Exception as e:
        print("DECODE FAILED", e)

    return sdk.gen_response(req, err_code, resp)

load_words()
