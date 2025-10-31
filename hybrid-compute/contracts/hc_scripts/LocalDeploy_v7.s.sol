// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import "@forge-std/src/Script.sol";
import "@account-abstraction/core/EntryPoint.sol";
import "hc_src/HCHelper.sol";
import "hc_src/HybridAccountFactory.sol";
import "hc_src/SimplePaymaster.sol";
import "@account-abstraction/samples/SimpleAccountFactory.sol";
import "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";

contract LocalDeploy is Script {
    function run() external
        returns (address[6] memory) {
        address deployAddr = vm.envAddress("DEPLOY_ADDR");
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address hcSysOwner = vm.envAddress("HC_SYS_OWNER");
        require (hcSysOwner != address(0), "HC_SYS_OWNER not set");
        uint256 deploySalt = vm.envOr("DEPLOY_SALT",uint256(0)); // Change this to force redeployment of contracts

        address bobaAddr = vm.envAddress("BOBA_TOKEN");

        EntryPoint ept;
        HCHelper helper;
        SimpleAccountFactory saf;
        HybridAccountFactory haf;
        HybridAccount ha0;
        SimplePaymaster pm;

        bytes32 salt_val = bytes32(deploySalt);
        uint112 min_deposit = 0.001 ether;
        uint256 pm_fund = 0.1 ether; // Currently uses this same value for staking

        vm.startBroadcast(deployerPrivateKey);

        // EntryPointAddr is hard-coded for the v0.7 implementation
        ept = EntryPoint(payable(0x0000000071727De22E5E9d8BAf0edAc6f37da032));

        {
            address helperAddr = vm.envOr("HC_HELPER_ADDR", 0x0000000000000000000000000000000000000000);
            if (helperAddr != address(0) && helperAddr.code.length > 0) {
                helper = HCHelper(helperAddr);
            } else {
                HCHelper helperImpl = new HCHelper{salt: salt_val}(address(ept));

                TransparentUpgradeableProxy hProxy = new TransparentUpgradeableProxy(
                  address(helperImpl),
                  hcSysOwner,
                  abi.encodeCall(HCHelper.initialize, (deployAddr))
                );
                helper = HCHelper(address(hProxy));
            }
        }
        {
            address safAddr = vm.envOr("SA_FACTORY_ADDR", 0x0000000000000000000000000000000000000000);
            if (safAddr != address(0) && safAddr.code.length > 0) {
                saf = SimpleAccountFactory(safAddr);
            } else {
                saf = new SimpleAccountFactory(ept);
            }
        }
        {
            address hafAddr = vm.envOr("HA_FACTORY_ADDR", 0x0000000000000000000000000000000000000000);
            if (hafAddr != address(0) && hafAddr.code.length > 0) {
                haf = HybridAccountFactory(hafAddr);
            } else {
                haf = new HybridAccountFactory(ept, address(helper));
            }
        }
        {
            address ha0Addr = vm.envOr("HC_SYS_ACCOUNT", 0x0000000000000000000000000000000000000000);
            if (ha0Addr != address(0) && ha0Addr.code.length > 0) {
                ha0 = HybridAccount(payable(ha0Addr));
            } else {
                ha0 = haf.createAccount(hcSysOwner,0);
            }
        }
        if (helper.systemAccount() != address(ha0)) {
            helper.SetSystemAccount(address(ha0));
        }

        // Previous version deposited to EntryPoint, here we fund the acct directly
        if (address(ha0).balance < min_deposit) {
            payable(address(ha0)).transfer(min_deposit - address(ha0).balance);
        }

        {
            SimplePaymaster.TokenPaymasterConfig memory pm_cfg;
            pm_cfg.priceMarkup = 1e26;
            pm_cfg.minEntryPointBalance = 0;
            pm_cfg.refundPostopCost = 10; // TODO figure out a suitable value
            pm_cfg.priceMaxAge = type(uint48).max;

            pm = new SimplePaymaster{salt: salt_val}(IERC20Metadata(address(0)),ept,IERC20(address(0)),pm_cfg,deployAddr, IERC20(bobaAddr));
            pm.setPrice(5e25);
            payable(address(pm)).transfer(pm_fund);
            ept.depositTo{value:pm_fund}(address(pm));
            pm.addStake{value:pm_fund}(3600);
        }

        vm.stopBroadcast();
        return [address(ept),address(helper), address(saf), address(haf), address(ha0), address(pm)];
    }
}
