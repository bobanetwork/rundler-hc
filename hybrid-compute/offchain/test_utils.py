""" Helper functions for HybridCompute tests + examples """
import json
import os
from typing import Optional
from dotenv import load_dotenv, find_dotenv

from web3 import Web3
from eth_abi import abi as ethabi

from hybrid_compute_sdk.server import HybridComputeSDK
from hybrid_compute_sdk.aa_client import AAClient, selector

class Bal:
    """Tracks the combined balance of an account"""

    def __init__(self, w3, ep, boba_token, price):
        self.w3 = w3
        self.ep = ep
        self.boba_token = boba_token
        self.price = price

        self.start_eth = {}
        self.start_ep = {}
        self.start_boba = {}

    def bal_boba(self, addr):
        """Returns the Boba token balance of an account"""
        boba_calldata = selector("balanceOf(address)") + \
             ethabi.encode(['address'], [addr])
        return Web3.to_int(self.w3.eth.call({'to':self.boba_token, 'data':boba_calldata}))

    def bal_ep(self, addr):
        """Returns the EntryPoint deposit balance of an account"""
        (bal_ep, _, _, _, _) = self.ep.functions.getDepositInfo(addr).call()
        return bal_ep

    def begin(self,addr):
        """Stores starting balances as the reference for an account"""
        self.start_eth[addr] = self.w3.eth.get_balance(addr)
        self.start_ep[addr] = self.bal_ep(addr)
        self.start_boba[addr] = self.bal_boba(addr)

    def now_total(self,addr):
        """Returns the current balance of an account relative to begin()"""
        now_eth = self.w3.eth.get_balance(addr) - self.start_eth[addr]
        now_ep = self.bal_ep(addr) - self.start_ep[addr]
        now_boba = self.bal_boba(addr) - self.start_boba[addr]

        now_total = now_eth + now_ep + \
            int((now_boba * self.price) / Web3.to_int(hexstr="0x52B7D2DCC80CD2E4000000"))
        return now_total

    def print_details(self,addr):
        """Prints details of a relative account balance"""
        now_eth = self.w3.eth.get_balance(addr) - self.start_eth[addr]
        now_ep = self.bal_ep(addr) - self.start_ep[addr]
        now_boba = self.bal_boba(addr) - self.start_boba[addr]

        now_total = now_eth + now_ep + \
            int((now_boba * self.price) / Web3.to_int(hexstr="0x52B7D2DCC80CD2E4000000"))
        return f"{now_eth:>18} {now_ep:>18} {now_boba:>18}B = {now_total:>18}"

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
        self.test_contracts = []
        self.contract_start_bal = {}

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

	# Default conversion price if no paymaster is used
        self.pm_price=Web3.to_int(hexstr="0x295BE96E64066972000000") # 5e25, or 0.5 after scaling
        self.pm_tokens = 0
        self.pm_sponsored = 0

        if self.paymaster:
            price_calldata = self.sdk.selector_hex("cachedPrice()")
            self.pm_price = Web3.to_int(
                self.w3.eth.call({'to':self.paymaster, 'data':price_calldata}))
        print("PRICE", self.pm_price)

        self.ep = self.eth_contract('EntryPoint')
        self.hh = self.eth_contract('HCHelper')
        self.ha = self.eth_contract('HybridAccount')
        self.bal = Bal(self.w3, self.ep, self.boba_token, self.pm_price)

        self.start_balances()

    def load_env(self):
        """ Load and validate configuration parameters from env variables """
    def eth_contract(self, name):
        """ Wrapper to get a contract API"""
        contract = self.w3.eth.contract(
            address=self.deployed[name]['address'],
            abi=self.deployed[name]['abi']
        )
        return contract

    def load_contract(self, name):
        """ Load a contract and register it for balance tracking """
        contract = self.eth_contract(name)
        if not contract.address in self.test_contracts:
            print(f"Registering contract {name} at {contract.address}")
            self.test_contracts.append(contract.address)
            self.bal.begin(contract.address)
        return contract

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
        print("GAS1", Web3.to_int(hexstr=op_receipt['actualGasCost']),
            Web3.to_int(hexstr=op_receipt['actualGasUsed']))
        print("GAS2", "used", Web3.to_int(hexstr= tx_rcpt['gasUsed']),
            "effPrice", Web3.to_int(hexstr=tx_rcpt['effectiveGasPrice']),
            "l1_price", Web3.to_int(hexstr=tx_rcpt['l1GasPrice']), "l1_used",
            Web3.to_int(hexstr=tx_rcpt['l1GasUsed']))
        print("GAS3", "bfscalar", Web3.to_int(hexstr=tx_rcpt['l1BaseFeeScalar']),
            "blob", Web3.to_int(hexstr=tx_rcpt['l1BlobBaseFee']), "blobscalar",
             Web3.to_int(hexstr=tx_rcpt['l1BlobBaseFeeScalar']),
             "fee", Web3.to_int(hexstr=tx_rcpt['l1Fee']))

        n = 0
        for i in tx_rcpt['logs']:
            # Special handling needed in case the topic has a leading 0x00....
            if log_topic:
                topic_str = str(Web3.to_hex(log_topic))
                if topic_str[2:].rjust(64,'0') == i['topics'][0][2:].rjust(64,'0'):
                    log_ret = (i['topics'], i['data'])
                print(f"*log {n} {i['topics'][0]} {i['data']}")
            elif Web3.to_bytes(hexstr=i['topics'][0][:10]) == \
                    selector("UserOperationSponsored(address,uint256,uint256,uint256)"):
                (token_charge, gas_cost, _token_price) = \
                    ethabi.decode(['uint256','uint256','uint256'], Web3.to_bytes(hexstr=i['data']))
                self.pm_tokens += token_charge
                self.pm_sponsored += gas_cost
                print(f" log {n} -> Paymaster token_charge {token_charge} gas_cost {gas_cost}")
            elif i['topics'][0][:10] == "0xddf252ad":
                a1 = Web3.to_checksum_address(str(i['topics'][1])[-40:])
                a2 = Web3.to_checksum_address(str(i['topics'][2])[-40:])
                (val,) = ethabi.decode(['uint256'],  Web3.to_bytes(hexstr=i['data']))
                print(f" log {n} -> Transfer {a1}->{a2} val {val}")
            elif i['topics'][0][:10] == "0xbb47ee3e":
                print(f" log {n} -> BeforeExecution()")
            elif i['topics'][0][:10] == "0x49628fd1":
                (_nonce, success, gas_cost, gas_used) = \
                    ethabi.decode(['uint256','bool','uint256','uint256'], \
                    Web3.to_bytes(hexstr=i['data']))
                print(f" log {n} -> UserOperationEvent success {success} "
                    f"gas_cost {gas_cost} gas_used {gas_used}")
            else:
                print(f" log {n} {i['topics'][0]} {i['data']}")
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

    def start_balances(self):
        """ Record the starting balances of system accounts. Called from __init__. """

        for a in self.bundler_addrs:
            self.bal.begin(a)
        self.bal.begin(self.client_addr)
        self.bal.begin(self.hh.address)
        self.bal.begin(self.ha.address)

        if self.paymaster:
            self.bal.begin(self.paymaster)

    def contract_net_balances(self):
        """Calculate the net change in ETH/Boba balances for registered contracts"""
        bal = 0
        for addr in self.test_contracts:
            bal += self.bal.now_total(addr)
        return bal

    def bal_print(self, baseline, w, amount):
        """ Helper to pretty-print an account's relative balance change"""
        pct = 100 * (amount / baseline)
        return f"{amount:>{w}} {pct:6.2f}%"

    def show_end_balances(self):
        """ Report the balance changes relative to start_balances """
        user_paid = -self.bal.now_total(self.client_addr)
        w = len(str(user_paid)) + 2

        bundler_profit = 0
        for a in self.bundler_addrs:
            bundler_profit += self.bal.now_total(a)
        pm_profit = self.bal.now_total(self.paymaster)
        hh_profit = self.bal.now_total(self.hh.address)
        ha_profit = self.bal.now_total(self.ha.address)
        contract_profit = self.contract_net_balances()
        l1_gas = self.op_gas_fees['l1Fees']
        l2_gas = self.op_gas_fees['l2Fees']
        residual = user_paid - (bundler_profit + pm_profit + contract_profit + \
            hh_profit + ha_profit + l1_gas + l2_gas)

        print(f"         User Paid: {user_paid:>{w}}")
        print("  Paymaster Profit:", self.bal_print(user_paid, w, pm_profit))
        print("    Bundler Profit:", self.bal_print(user_paid, w, bundler_profit))
        print("   HCHelper Profit:", self.bal_print(user_paid, w, hh_profit))
        print(" HybridAcct Profit:", self.bal_print(user_paid, w, ha_profit))
        print("   Contract Profit:", self.bal_print(user_paid, w, contract_profit))
        print("            L1 Gas:", self.bal_print(user_paid, w, l1_gas))
        print("            L2 Gas:", self.bal_print(user_paid, w, l2_gas))
        print("          Residual:", self.bal_print(user_paid, w, residual))

        # A small residual is "normal" but large amounts can indicate e.g.
        # duplicate/stale bundle submissions.
        assert residual < 10

    def show_balance_details(self):
        """
        Show the current balances of system accounts, individually reporting
        the account ETH, EntryPoint deposit, and Boba balance
        """

        print("     Client Addr:", self.bal.print_details(self.client_addr))
        for a in self.bundler_addrs:
            print("         Bundler:",self.bal.print_details(a))
        if self.paymaster:
            print("       Paymaster:", self.bal.print_details(self.paymaster))
        print("        HCHelper:", self.bal.print_details(self.hh.address))
        print("  Hybrid Account:", self.bal.print_details(self.ha.address))
        for c in self.test_contracts:
            print("   Test Contract:", self.bal.print_details(c))

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
