"""Offchain handler for the Hybrid Compute sports betting example"""
from web3 import Web3
from eth_abi import abi as ethabi
from hybrid_compute_sdk.server import HybridComputeSDK

def get_handlers():
    """Return the method signatures and the associated handlers"""
    print("--> get_score(uint256)")
    return [("get_score(uint256)",      offchain_sports_betting)]

def offchain_sports_betting(ver, sk, src_addr, src_nonce, oo_nonce, payload, *args):
    """Offchain handler for the Hybrid Compute sports betting example"""
    print(f"  -> offchain_sport_betting handler called with subkey={sk} "
        f"src_addr={src_addr} src_nonce={src_nonce} oo_nonce={oo_nonce} "
        f"payload={payload} extra_args={args}"
    )
    err_code = 0
    resp = Web3.to_bytes(text="unknown error")
    assert ver == "0.3"
    sdk = HybridComputeSDK()

    try:
        req = sdk.parse_req(sk, src_addr, src_nonce, oo_nonce, payload)
        (game_id,) = ethabi.decode(['uint256'], req['reqBytes'])

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

    return sdk.gen_response(req, err_code, resp)

def get_game_score(game_id):
    """
    This is a dummy function to simulate the offchain data retrieval
    In a real-world scenario, this function would query an API
    to get the game score
    """
    if game_id == "123":
        return [2, 1]
    if game_id == "456":
        return [0, 3]
    return [0, 0]
