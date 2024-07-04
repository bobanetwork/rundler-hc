
from web3 import Web3
from eth_abi import abi as ethabi
from offchain_utils import gen_response, parse_req


def offchain_sports_betting(ver, sk, src_addr, src_nonce, oo_nonce, payload, *args):
    print("  -> offchain_sport_betting handler called with subkey={} src_addr={} src_nonce={} oo_nonce={} payload={} extra_args={}".format(sk,
          src_addr, src_nonce, oo_nonce, payload, args))
    err_code = 0
    resp = Web3.to_bytes(text="unknown error")

    try:
        req = parse_req(sk, src_addr, src_nonce, oo_nonce, payload)
        dec = ethabi.decode(['uint256'], req['reqBytes'])

        game_id = dec[0]
        print("offchain game_id:", game_id)
        score = get_game_score(game_id)
        end_result = 0
        if score[0] > score[1]:
            end_result = 1
        elif score[0] < score[1]:
            end_result = 2
        else:
            end_result = 3
        
        print("End result: ", end_result)
        resp = ethabi.encode(['uint256'], [end_result])
    except Exception as e:
        resp = ethabi.encode(["bool"], [False])
        err_code = 1
        print("DECODE FAILED", e)

    return gen_response(req, err_code, resp)


def get_game_score(game_id):
    # This is a dummy function to simulate the offchain data retrieval
    # In a real-world scenario, this function would query an API
    # to get the game score
    if game_id == "123":
        return [2, 1]
    elif game_id == "456":
        return [0, 3]
    else:
        return [0, 0]
