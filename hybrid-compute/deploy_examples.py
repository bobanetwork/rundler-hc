""" Deploys local HybridCompute examples. Call deploy_local.py first."""

import json
from web3 import Web3
from eth_abi import abi as ethabi

from hybrid_compute_sdk.aa_client import AAClient, selector
from hybrid_compute_sdk.deploy import Deploy

class ExampleDeploy:
    def __init__(self):
        self.d = Deploy()
        self.env_vars = {}

        print("Reading .env")
        with open(".env", "r", encoding="ascii") as f:
            for line in f.readlines():
                if line.startswith('#'):
                    continue
                if self.d.cli_args.kms_port:
                    # Override the hardcoded keys
                    if line.startswith("SIGNER_PRIVATE_KEY") or line.startswith("BUNDLER_ADDR"):
                        continue
                k,v = line.strip().split('=')
                self.env_vars[k] = v
        print("Loading deployed contracts")
        with open("./contracts.json", "r", encoding="ascii") as f:
            self.d.deployed = json.loads(f.read())

        # FIXME
        ep_addr = self.env_vars['ENTRY_POINTS']
        self.d.entry_point = self.d.load_contract("EntryPoint", ep_addr, "./contracts/v0_7/out/EntryPoint.sol/EntryPoint.json")

    def random_fees(self, contract, fee, pay):
        """Sets the token fee charged/paid by the VRF contract"""
        print("Setting VRF fees")
        tx = contract.functions.SetFees(fee, pay).build_transaction({
            'from': self.d.deploy_addr,
        })
        self.d.l2_util.sign_and_submit(tx, self.d.deploy_key)


    def deploy_examples(self,hybrid_acct_addr):
        """Deploy example contracts"""
        cmd_env = {}
        cmd_env['OC_HYBRID_ACCOUNT'] = hybrid_acct_addr
        cmd_env['BOBA_TOKEN'] = self.d.boba_token
        cmd_env['OC_RANDOM_KEYHASH'] = self.env_vars['OC_RANDOM_KEYHASH']
        addrs = self.d.deploy_forge("hc_scripts/ExampleDeploy_v7.s.sol", cmd_env)

        print("Deployed example contracts:", addrs)
        return addrs.split(',')

    def deploy(self):
        haf_addr = self.env_vars['HA_FACTORY_ADDR']
        hh_addr = self.env_vars['HC_HELPER_ADDR']
        helper = self.d.load_contract('HCHelper', hh_addr)   

        ha1_addr = self.d.deploy_account(haf_addr, self.d.env_vars['OC_OWNER'])
        self.d.fund_addr(ha1_addr)

        hybrid_acct = self.d.load_contract('HybridAccount', ha1_addr)

        local_url = "http://" + str(self.d.local_ip) + ":1234/hc"
        self.d.register_url(helper, ha1_addr, local_url)

        self.env_vars['OC_HYBRID_ACCOUNT'] = ha1_addr

        example_addrs = self.deploy_examples(ha1_addr)
        self.d.load_contract('TestAuctionSystem', example_addrs[0], "./contracts/v0_7/out/TestAuctionSystem.sol/AuctionFactory.json")
        self.d.load_contract('TestCaptcha', example_addrs[1])
        self.d.load_contract('TestHybrid', example_addrs[2])
        self.d.load_contract('TestRainfallInsurance', example_addrs[3], "./contracts/v0_7/out/TestRainfallInsurance.sol/RainfallInsurance.json")
        self.d.load_contract('TestSportsBetting', example_addrs[4], "./contracts/v0_7/out/TestSportsBetting.sol/SportsBetting.json")
        self.d.load_contract('TestKyc', example_addrs[5])
        self.d.load_contract('TestTokenPrice', example_addrs[6])
        test_random = self.d.load_contract('TestRandom', example_addrs[7])

        for a in example_addrs:
            self.d.permit_caller(ha1_addr, a)

        client_addr = self.env_vars['CLIENT_ADDR']
        self.d.approve_boba(client_addr, test_random.address)
        self.random_fees(test_random, Web3.to_wei(0.02, "ether"), Web3.to_wei(0.01, "ether"))

       # Allow HybridAccount to re-register its URL
        self.d.env_vars['OC_ALLOW_REG'] = ha1_addr

        # Used by aa-hc-check.sh
        self.env_vars['TEST_HYBRID'] = example_addrs[2]

        print("Updating .env file")
        self.d.save_deployed()
        self.d.save_env(self.env_vars)

ExampleDeploy().deploy()
