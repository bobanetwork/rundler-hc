import re
import random
from web3 import Web3
from eth_abi import abi as ethabi
from offchain_utils import gen_response, parse_req


def load_words():
    wordlist = []
    with open("/usr/share/dict/words", "r") as f:
        p = re.compile('^[a-z]{4}$')
        for line in f.readlines():
            line = line.strip()
            if p.match(line) and line != "frog":  # Reserved for "cheat" mode
                wordlist.append(line)
    return wordlist


wordlist = load_words()


def offchain_ramble(sk, src_addr, src_nonce, oo_nonce, payload, *args):
    global wordlist
    print("  -> offchain_ramble handler called with subkey={} src_addr={} src_nonce={} oo_nonce={} payload={} extra_args={}".format(sk,
          src_addr, src_nonce, oo_nonce, payload, args))
    err_code = 1
    resp = Web3.to_bytes(text="unknown error")

    try:
        req = parse_req(sk, src_addr, src_nonce, oo_nonce, payload)
        dec = ethabi.decode(['uint256', 'bool'], req['reqBytes'])
        n = dec[0]
        cheat = dec[1]
        words = []

        if n >= 1 and n < 1000:
            for i in range(n):
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

    return gen_response(req, err_code, resp)
