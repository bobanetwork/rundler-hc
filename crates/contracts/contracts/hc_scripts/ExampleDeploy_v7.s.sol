// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import "../common/lib/forge-std/src/Script.sol";
import "hc_src/HybridAccount.sol";
import "hc_src/TestAuctionSystem.sol";
import "hc_src/TestCaptcha.sol";
import "hc_src/TestHybrid.sol";
import "hc_src/TestRainfallInsurance.sol";
import "hc_src/TestSportsBetting.sol";
import "hc_src/TestKyc.sol";
import "hc_src/TestTokenPrice.sol";
import "hc_src/TestRandom.sol";
import "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";

contract LocalDeploy is Script {
    function run() external
        returns (address[8] memory) {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address deployAddr = vm.envAddress("DEPLOY_ADDR");
        uint256 deploySalt = vm.envOr("DEPLOY_SALT",uint256(0)); // Change this to force redeployment of contracts
        bytes32 salt_val = bytes32(deploySalt);

        address payable ha1Addr = payable(vm.envAddress("OC_HYBRID_ACCOUNT"));
        address bobaAddr = vm.envAddress("BOBA_TOKEN");
        require (bobaAddr != address(0), "bobaAddr missing");
        bytes32 ocRandomKeyHash = bytes32(vm.envUint("OC_RANDOM_KEYHASH"));
        require (ocRandomKeyHash != bytes32(0), "randomKeyHash missing");
        HybridAccount ha1;

        address[8] memory ret;

        vm.startBroadcast(deployerPrivateKey);

        ret[0] = address(new AuctionFactory(ha1Addr));
        ret[1] = address(new TestCaptcha(ha1Addr));
        ret[2] = address(new TestHybrid(ha1Addr));
        ret[3] = address(new RainfallInsurance(ha1Addr));
        ret[4] = address(new SportsBetting(ha1Addr));
        ret[5] = address(new TestKyc(ha1Addr));
        ret[6] = address(new TestTokenPrice(ha1Addr));
//        ret[7] = address(new TestRandom(ha1Addr, bobaAddr, ocRandomKeyHash));
        {
            TestRandom vrfImpl = new TestRandom{salt: salt_val}(ha1Addr, bobaAddr);
            TransparentUpgradeableProxy vrfProxy = new TransparentUpgradeableProxy(
              address(vrfImpl),
              deployAddr,
              abi.encodeCall(TestRandom.initialize, (deployAddr, ocRandomKeyHash))
            );
            ret[7] = address(vrfProxy);
        }
        vm.stopBroadcast();
        return ret;
    }
}
