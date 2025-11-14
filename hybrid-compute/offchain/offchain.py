"""Run an offchain Hybrid Compute JSON-RPC server with several examples"""

import os
from dotenv import load_dotenv, find_dotenv
from hybrid_compute_sdk.server import HybridComputeSDK

load_dotenv(find_dotenv())

def server_loop():
    """Register handlers and launch the server"""
    load_dotenv(find_dotenv())
    port = int(os.environ['OC_LISTEN_PORT'])
    assert port != 0

    sdk = HybridComputeSDK()
    sdk.create_json_rpc_server_instance('0.0.0.0', port)
    sdk.register_handlers("./offchain/handlers")
    sdk.serve_forever()

server_loop()
