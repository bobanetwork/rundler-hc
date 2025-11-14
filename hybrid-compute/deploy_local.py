""" Deploys a local HybridCompute system on top of a Boba local devnet"""

from web3 import Web3
from eth_abi import abi as ethabi

from hybrid_compute_sdk.aa_client import AAClient, selector
from hybrid_compute_sdk.deploy import Deploy

class LocalDeploy:
    def __init__(self):
        self.d = Deploy()

    def deploy(self):
        """Main function to perform the deployment"""

        self.d.fund_deployer()
        for addr in self.d.env_vars['BUNDLER_ADDR_LIST'].split(','):
            self.d.fund_addr(addr)

        self.d.build_forge()
        (ep_addr, hh_addr, saf_addr, haf_addr, ha0_addr, pm_addr) = self.d.deploy_base()
        self.d.entry_point = self.d.load_contract("EntryPoint", ep_addr, "./contracts/v0_7/out/EntryPoint.sol/EntryPoint.json")

        helper = self.d.load_contract('HCHelper', hh_addr)
        self.d.l2_util.approve_token(self.d.boba_token, helper.address,
            self.d.deploy_addr, self.d.deploy_key)

        tx = helper.functions.SetPaymentInfo(self.d.boba_token,
            Web3.to_wei(0.1,'ether'), 1000000). build_transaction({
            'from': self.d.deploy_addr,
        })
        self.d.l2_util.sign_and_submit(tx, self.d.deploy_key)

        client_addr = self.d.deploy_account(saf_addr, self.d.env_vars['CLIENT_OWNER'])
        self.d.fund_addr(client_addr)

        t_calldata = selector("transfer(address,uint256)") + \
            ethabi.encode(['address','uint256'], [client_addr, Web3.to_wei(10,'ether')])
        t_tx = {
            'from':self.d.deploy_addr,
            'data':t_calldata,
            'to':self.d.boba_token,
        }
        self.d.l2_util.sign_and_submit(t_tx, self.d.deploy_key)
        self.d.approve_boba(client_addr, pm_addr)

        self.d.save_deployed()

        # self.d.deployed addresses
        self.d.env_vars['ENTRY_POINTS'] = self.d.entry_point.address
        self.d.env_vars['HC_HELPER_ADDR'] = helper.address
        self.d.env_vars['HC_SYS_ACCOUNT'] = ha0_addr

        self.d.env_vars['CLIENT_ADDR'] = client_addr
        self.d.env_vars['SA_FACTORY_ADDR'] = saf_addr
        self.d.env_vars['HA_FACTORY_ADDR'] = haf_addr

        # Other
        self.d.env_vars['BOBA_TOKEN'] = self.d.boba_token
        self.d.env_vars['SIMPLE_PM'] = pm_addr
        self.d.env_vars['NODE_HTTP'] = self.d.eth_url
        self.d.env_vars['OC_NODE_HTTP'] = self.d.env_vars['NODE_HTTP']
        self.d.env_vars['CHAIN_ID'] = self.d.chain_id

        print("Writing .env file")
        self.d.save_env()

LocalDeploy().deploy()
