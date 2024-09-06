# Some common functions for working with UserOperations and Transactions
from web3 import Web3
from eth_abi import abi as ethabi
import eth_account

# Provides some AA helper functions
class aa_utils:
    def __init__(self, _EP_addr, _chain_id):
        self.EP_addr = _EP_addr
        self.chain_id = _chain_id

    def sign_op(self, op, signer_key):
        """Signs a UserOperation, returning a modified op containing a 'signature' field."""
        pack1 = ethabi.encode(['address','uint256','bytes32','bytes32','uint256','uint256','uint256','uint256','uint256','bytes32'], \
              [op['sender'],
              Web3.to_int(hexstr=op['nonce']),
              Web3.keccak(hexstr=op['initCode']),
              Web3.keccak(hexstr=op['callData']),
              Web3.to_int(hexstr=op['callGasLimit']),
              Web3.to_int(hexstr=op['verificationGasLimit']),
              Web3.to_int(hexstr=op['preVerificationGas']),
              Web3.to_int(hexstr=op['maxFeePerGas']),
              Web3.to_int(hexstr=op['maxPriorityFeePerGas']),
              Web3.keccak(hexstr=op['paymasterAndData']),
              ])
        pack2 = ethabi.encode(['bytes32','address','uint256'], [Web3.keccak(pack1), self.EP_addr, self.chain_id])
        e_msg = eth_account.messages.encode_defunct(Web3.keccak(pack2))
        signer_acct = eth_account.account.Account.from_key(signer_key)
        sig = signer_acct.sign_message(e_msg)
        op['signature'] = Web3.to_hex(sig.signature)
        return op

class aa_rpc(aa_utils):
    """Provides AA helper methods which talk to an ETH node and/or a Bundler"""
    def __init__(self, _EP_addr, _eth_rpc, _bundler_url):
        self.w3 = _eth_rpc
        self.bundler_url = _bundler_url
        aa_utils.__init__(self, _EP_addr, self.w3.eth.chain_id)

    def aa_nonce(self, addr, key):
        """Returns the keyed AA nonce for an address"""
        calldata = selector("getNonce(address,uint192)") + ethabi.encode(['address','uint192'],[addr, key])
        ret = self.w3.eth.call({'to':self.EP_addr,'data':calldata})
        return Web3.to_hex(ret)

class eth_utils:
    """Provides some helper functions for EOA transactions and general utilities"""
    def __init__(self, _w3):
        self.w3 = _w3
        self.chain_id = self.w3.eth.chain_id

    def sign_and_submit(self, tx, key):
        """Wrapper to sign and submit an Eth transaction from an EOA (e.g. the deployer account)
           Will populate some fields automatically while allowing the original Tx to override."""
        if 'nonce' not in tx:
            tx['nonce'] = self.w3.eth.get_transaction_count(tx['from'])
        if 'chainId' not in tx:
            tx['chainId'] = self.chain_id
        est = self.w3.eth.estimate_gas(tx)
        if 'gas' not in tx or tx['gas'] < est:
            tx['gas'] = est
        if 'gasPrice' not in tx and 'maxFeePerGas' not in tx:
            tx['gasPrice'] = self.w3.eth.gas_price

        signed_txn = self.w3.eth.account.sign_transaction(tx, key)
        ret = self.w3.eth.send_raw_transaction(signed_txn.rawTransaction)
        rcpt = self.w3.eth.wait_for_transaction_receipt(ret)
        if rcpt.status != 1:
            print("Transaction failed, txhash =", Web3.to_hex(ret))
        assert rcpt.status == 1
        return rcpt

    def approve_token(self, token, spender, deploy_addr, deploy_key):
        """Perform an unlimited ERC20 token approval"""
        approveCD = selector("approve(address,uint256)") + ethabi.encode(
            ['address','uint256'],
            [spender, Web3.to_int(hexstr="0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")])

        tx = {
            'from': deploy_addr,
            'data': approveCD,
            'to': token,
        }
        print("ERC20 approval of", token, "for", spender)
        self.sign_and_submit(tx, deploy_key)

# Utility functions which don't need an RPC or Endpoint context

def selector(name):
    """Return a Solidity-style function selector, e.g. 0x1234abcd = keccak256("something(uint,bool")"""
    name_hash = Web3.to_hex(Web3.keccak(text=name))
    return Web3.to_bytes(hexstr=str(name_hash)[:10])
