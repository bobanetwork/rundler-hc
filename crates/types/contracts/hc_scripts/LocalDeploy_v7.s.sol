// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import "forge-std/Script.sol";
import "lib/account-abstraction-versions/v0_7/contracts/core/EntryPoint.sol";
import "src/hc0_7/HCHelper.sol";
import "src/hc0_7/HybridAccountFactory.sol";
import "lib/account-abstraction-versions/v0_7/contracts/samples/SimpleAccountFactory.sol";

contract LocalDeploy is Script {
    function run() external
        returns (address[5] memory) {
        address deployAddr = vm.envAddress("DEPLOY_ADDR");
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address hcSysOwner = vm.envAddress("HC_SYS_OWNER");
        require (hcSysOwner != address(0), "HC_SYS_OWNER not set");
        uint256 deploySalt = vm.envOr("DEPLOY_SALT",uint256(0)); // Change this to force redeployment of contracts

        address bobaAddr = vm.envOr("BOBA_TOKEN", 0x4200000000000000000000000000000000000023);

        EntryPoint ept;
        HCHelper helper;
        SimpleAccountFactory saf;
        HybridAccountFactory haf;
        HybridAccount ha0;

        bytes32 salt_val = bytes32(deploySalt);
        uint112 min_deposit = 0.001 ether;

        vm.startBroadcast(deployerPrivateKey);

        // EntryPointAddr is hard-coded for the v0.7 implementation
        ept = EntryPoint(payable(0x0000000071727De22E5E9d8BAf0edAc6f37da032));

        {
            address helperAddr = vm.envOr("HC_HELPER_ADDR", 0x0000000000000000000000000000000000000000);
            if (helperAddr != address(0) && helperAddr.code.length > 0) {
                helper = HCHelper(helperAddr);
            } else {
                helper = new HCHelper{salt: salt_val}(address(ept), bobaAddr, deployAddr);
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

        vm.stopBroadcast();
        return [address(ept),address(helper), address(saf), address(haf), address(ha0)];
    }
}
