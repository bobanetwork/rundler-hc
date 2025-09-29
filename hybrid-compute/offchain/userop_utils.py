""" Helper functions for HybridCompute tests + examples """
import json
import os
from typing import Optional
from dotenv import load_dotenv, find_dotenv

from web3 import Web3
from eth_abi import abi as ethabi

from hybrid_compute_sdk.server import HybridComputeSDK
from hybrid_compute_sdk.aa_client import AAClient, selector

class TestUtils:
    """ Helper functions for HybridCompute tests + examples """
    def __init__(
        self,
        node_url: Optional[str] = None,
        bundler_url: Optional[str] = None,
        client_addr:  Optional[str] = None,
        client_owner:  Optional[str] = None,
        client_key:  Optional[str] = None,
    ):
        load_dotenv(find_dotenv())
        self.sdk = HybridComputeSDK()

        with open("./contracts.json", "r", encoding="ascii") as f:
            self.deployed = json.loads(f.read())

        self.node_url = node_url or os.getenv('NODE_HTTP')
        self.bundler_url = bundler_url or os.getenv('BUNDLER_RPC')
        self.aa = AAClient(node_url=self.node_url, bundler_url=self.bundler_url)

        client_addr = client_addr or os.environ['CLIENT_ADDR']
        assert len(client_addr) == 42
        self.client_addr = Web3.to_checksum_address(client_addr)

        # Owner of the user account used to submit client requests
        client_owner = client_owner or os.environ['CLIENT_OWNER']
        assert len(client_owner) == 42
        self.client_owner = Web3.to_checksum_address(client_owner)

        # Private key for client_owner
        client_key = os.environ['CLIENT_PRIVATE_KEY']
        assert len(client_key) == 66
        self.client_key = client_key

        # Initialize Web3 connection
        self.w3 = Web3(Web3.HTTPProvider(self.node_url))
        if not self.w3.is_connected:
            raise ConnectionError(f"Failed to connect to node at {self.node_url}")

        # Generates an AA-style nonce (each key has its own associated sequence count)
        self.nonce_key = int(1200 + (self.w3.eth.get_transaction_count(self.client_addr) % 7))

        self.paymaster = None
        if 'SIMPLE_PM' in os.environ:
            pm_addr = os.environ['SIMPLE_PM']
            assert pm_addr == Web3.to_checksum_address(pm_addr)
            self.paymaster = pm_addr

        self.bundler_addrs = os.environ['BUNDLER_ADDR_LIST'].split(',')
        for a in self.bundler_addrs:
            assert a == Web3.to_checksum_address(a)

        boba_token = os.environ['BOBA_TOKEN']
        assert len(boba_token) == 42
        self.boba_token = Web3.to_checksum_address(boba_token)

        # Tracks gas between estimate and receipt. Could generalize to store as a dict
        # keyed by op_hash, but for now we only do 1 op at a time.
        self.op_gas_fees = {}
        self.op_gas_fees['estGas'] = 0
        self.op_gas_fees['l2Fees'] = 0   # Cumulative L2 fees
        self.op_gas_fees['l1Fees'] = 0   # Cumulative L1 fees

        self.start_balances()

    def load_env(self):
        """ Load and validate configuration parameters from env variables """

    def eth_contract(self, name):
        """ Wrapper for w3.eth.contract() """
        return self.w3.eth.contract(
            address=self.deployed[name]['address'],
            abi=self.deployed[name]['abi']
        )

    def selector(self, name):
        """ Wrapper to return a function selector """
        return self.sdk.selector_hex(name)

    def build_op(self, contract, value, calldata):
        """ Wrapper to build a UserOperation """
        return self.aa.build_op(
            self.client_addr,
            self.deployed[contract]['address'],
            value,
            calldata,
            self.nonce_key,
            self.paymaster
        )

    def estimate_op(self, op):
        """ Wrapper to estimate gas of a UserOperation """
        (success, op) = self.aa.estimate_op_gas(op)
        if not success:
            return False, op

        self.op_gas_fees['estGas'] = Web3.to_int(hexstr=op['preVerificationGas']) \
            + Web3.to_int(hexstr=op['verificationGasLimit']) \
            + Web3.to_int(hexstr=op['callGasLimit'])
        if 'paymasterVerificationGasLimit' in op:
            self.op_gas_fees['estGas'] += Web3.to_int(hexstr=op['paymasterVerificationGasLimit'])
        print("estimateGas total =", self.op_gas_fees['estGas'])
        print("-----")
        return True, op

    def submit_op(self, op):
        """ Wrapper to sign and submit a UserOperation """
        return self.aa.sign_submit_op(op, self.client_key)

    def parse_receipt(self, op_receipt, log_topic=None):
        """Parses an operation receipt to extract gas information. Can optionally look
           for one specified log topic and return a matching entry. Sufficient for the
           current examples but not intended as a general solution."""
        tx_rcpt = op_receipt['receipt']
        log_ret = None

        n = 0
        for i in tx_rcpt['logs']:
            print("log", n, i['topics'][0], i['data'])
            # Special handling needed in case the topic has a leading 0x00....
            if log_topic:
                topic_str = str(Web3.to_hex(log_topic))
                if topic_str[2:].rjust(64,'0') == i['topics'][0][2:].rjust(64,'0'):
                    log_ret = (i['topics'], i['data'])
            n += 1
        if 'l1GasUsed' not in tx_rcpt:
            tx_rcpt['l1GasUsed'] = "0x0"
        if 'l1Fee' not in tx_rcpt:
            tx_rcpt['l1Fee'] = "0x0"

        print("Total tx gas stats:",
              "gasUsed", Web3.to_int(hexstr=tx_rcpt['gasUsed']),
              "effectiveGasPrice", Web3.to_int(hexstr=tx_rcpt['effectiveGasPrice']),
              "l1GasUsed", Web3.to_int(hexstr=tx_rcpt['l1GasUsed']),
              "l1Fee", Web3.to_int(hexstr=tx_rcpt['l1Fee']))
        op_gas = Web3.to_int(hexstr=op_receipt['actualGasUsed'])
        print("op_receipt gas used", op_gas, "unused", self.op_gas_fees['estGas'] - op_gas)

        eg_price = Web3.to_int(hexstr=tx_rcpt['effectiveGasPrice'])
        self.op_gas_fees['l2Fees'] += Web3.to_int(hexstr=tx_rcpt['gasUsed']) * eg_price
        self.op_gas_fees['l1Fees'] += Web3.to_int(hexstr=tx_rcpt['l1Fee'])

        return log_ret

    def boba_balance(self, addr):
        """Returns the Boba token balance of an address"""
        bal_calldata = self.sdk.selector_hex("balanceOf(address)") + \
             ethabi.encode(['address'], [addr])
        bal = self.w3.eth.call({'to':self.boba_token, 'data':bal_calldata})
        return Web3.to_int(bal)

    def start_balances(self):
        """ Record the starting balances of system accounts. Called from __init__. """
        ep = self.eth_contract('EntryPoint')
        self.bal_start_bnd = 0
        for a in self.bundler_addrs:
            self.bal_start_bnd += self.w3.eth.get_balance(a)
        self.bal_start_sa = ep.functions.getDepositInfo(self.client_addr).call()[0] + \
            self.w3.eth.get_balance(self.client_addr)
        self.bal_start_boba = self.boba_balance(self.client_addr)

        self.bal_start_pm = 0
        if self.paymaster:
            self.bal_start_pm = ep.functions.getDepositInfo(self.paymaster).call()[0]

    def show_end_balances(self):
        """ Report the balance changes relative to start_balances() """
        ep = self.eth_contract('EntryPoint')
        bal_final_bnd = 0
        for a in self.bundler_addrs:
            bal_final_bnd += self.w3.eth.get_balance(a)
        bal_final_sa = ep.functions.getDepositInfo(self.client_addr).call()[0] + \
            self.w3.eth.get_balance(self.client_addr)
        bal_final_boba = self.boba_balance(self.client_addr)

        print("Net balance changes",
            bal_final_bnd - self.bal_start_bnd,
            bal_final_sa - self.bal_start_sa,
            (bal_final_bnd + bal_final_sa) - (self.bal_start_bnd + self.bal_start_sa),
            (self.op_gas_fees['l1Fees'] + self.op_gas_fees['l2Fees'])
        )

        pm_profit = 0
        user_paid = self.bal_start_sa - bal_final_sa
        if self.paymaster:
            price_calldata = self.sdk.selector_hex("cachedPrice()")
            price = Web3.to_int(self.w3.eth.call({'to':self.paymaster, 'data':price_calldata}))
            paid_boba = self.bal_start_boba - bal_final_boba
            # SimplePaymaster.sol scales prices by PRICE_DENOMINATOR = 1e26
            user_paid_pm = int((paid_boba * price) / Web3.to_int(hexstr="0x52B7D2DCC80CD2E4000000"))
            bal_final_pm = ep.functions.getDepositInfo(self.paymaster).call()[0]
            pm_paid = self.bal_start_pm - bal_final_pm
            pm_profit = user_paid_pm - pm_paid
            #print(f"User account paid {user_paid} to PM")
            #print(f"Paymaster paid {pm_paid}")
            user_paid += user_paid_pm

        print("User account paid:  ", user_paid)

        assert user_paid > 0
        bundler_profit = bal_final_bnd - self.bal_start_bnd

        print("     Bundler profit:", bundler_profit, 100*(bundler_profit / user_paid), "%")
        print("   Paymaster profit:", pm_profit, 100*(pm_profit / user_paid), "%")
        print("             L2 gas:", self.op_gas_fees['l2Fees'],
            100*(self.op_gas_fees['l2Fees'] / user_paid), "%"
        )
        print("             L1 fee:", self.op_gas_fees['l1Fees'],
            100*(self.op_gas_fees['l1Fees'] / user_paid), "%"
        )
        print("           Residual:",
            user_paid - (bundler_profit + pm_profit + \
            self.op_gas_fees['l2Fees'] + self.op_gas_fees['l1Fees'])
        )

    def show_balances(self):
        """ Show the current balances of system accounts """

        ep = self.eth_contract('EntryPoint')
        hh = self.eth_contract('HCHelper')
        ha = self.eth_contract('HybridAccount')

        print("    CLIENT_ADDR", ep.functions.getDepositInfo(
            self.client_addr).call(), self.w3.eth.get_balance(self.client_addr))
        for a in self.bundler_addrs:
            print("    BUNDLER_ADDR", a, ep.functions.getDepositInfo(
                a).call(), self.w3.eth.get_balance(a))
        print("    OC_HYBRID_ACCOUNT ", ep.functions.getDepositInfo(
            ha.address).call(), self.w3.eth.get_balance(ha.address))
        print("    Helper BOBA token:", self.boba_balance(hh.address))
        print("    HybridAcct BOBA token:", self.boba_balance(ha.address))
        print("    Client BOBA token:", self.boba_balance(self.client_addr))

class EthUtils:
    """
    Provides some helper functions for EOA transactions and general utilities.
    Used by deploy-local.py
    """
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
        approve_calldata = selector("approve(address,uint256)") + ethabi.encode(
            ['address','uint256'],
            [spender, Web3.to_int(hexstr=\
                "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")])

        tx = {
            'from': deploy_addr,
            'data': approve_calldata,
            'to': token,
        }
        print("ERC20 approval of", token, "for", spender)
        self.sign_and_submit(tx, deploy_key)
