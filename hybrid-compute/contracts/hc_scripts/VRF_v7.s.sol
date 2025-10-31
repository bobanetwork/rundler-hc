// SPDX-License-Identifier: UNLICENSED
// forge script --json --broadcast --via-ir --rpc-url <url> --contracts src/hc0_7 \
//   --remappings @openzeppelin/=lib/openzeppelin-contracts-versions/v5_0
//   --verifier-url <vfy> \
//   hc_scripts/CoreDeploy_v7.sol

pragma solidity ^0.8.23;

import "forge-std/Script.sol";
import "lib/account-abstraction-versions/v0_7/contracts/core/EntryPoint.sol";
import "src/hc0_7/HCHelper.sol";
import "src/hc0_7/HybridAccountFactory.sol";
import "src/hc0_7/TestRandom.sol";

import "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";

contract CoreDeploy is Script {
    function run() external
        returns (address) {

       uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address deployAddr = vm.envAddress("DEPLOY_ADDR");
        uint256 deploySalt = vm.envOr("DEPLOY_SALT",uint256(0)); // Change this to force redeployment of contracts
        bytes32 salt_val = bytes32(deploySalt);

        address payable ha1Addr = payable(vm.envAddress("OC_HYBRID_ACCOUNT"));
        address bobaAddr = vm.envAddress("BOBA_TOKEN");
        require (bobaAddr != address(0), "bobaAddr missing");
        bytes32 ocRandomKeyHash = bytes32(vm.envUint("OC_RANDOM_KEYHASH"));
        require (ocRandomKeyHash != bytes32(0), "randomKeyHash missing");

        vm.startBroadcast(deployerPrivateKey);


            TestRandom vrfImpl = new TestRandom{salt: salt_val}(ha1Addr, bobaAddr);
            TransparentUpgradeableProxy vrfProxy = new TransparentUpgradeableProxy(
              address(vrfImpl),
              deployAddr,
              abi.encodeCall(TestRandom.initialize, (deployAddr, ocRandomKeyHash))
            );
            address ret = address(vrfProxy);

        vm.stopBroadcast();
        return ret;

    }
}
