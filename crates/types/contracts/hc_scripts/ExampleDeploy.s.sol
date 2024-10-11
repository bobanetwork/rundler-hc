// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Script.sol";
import "src/hc0_6/HybridAccount.sol";
import "src/hc0_6/TestAuctionSystem.sol";
import "src/hc0_6/TestCaptcha.sol";
import "src/hc0_6/TestHybrid.sol";
import "src/hc0_6/TestRainfallInsurance.sol";
import "src/hc0_6/TestSportsBetting.sol";
import "src/hc0_6/TestKyc.sol";
import "src/hc0_6/TestTokenPrice.sol";

contract LocalDeploy is Script {
    function run() external 
        returns (address[7] memory) {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");

        address payable ha1Addr = payable(vm.envAddress("OC_HYBRID_ACCOUNT"));
        HybridAccount ha1;

        address[7] memory ret;

        vm.startBroadcast(deployerPrivateKey);

        ret[0] = address(new AuctionFactory(ha1Addr));
        ret[1] = address(new TestCaptcha(ha1Addr));
        ret[2] = address(new TestHybrid(ha1Addr));
        ret[3] = address(new RainfallInsurance(ha1Addr));
        ret[4] = address(new SportsBetting(ha1Addr));
        ret[5] = address(new TestKyc(ha1Addr));
        ret[6] = address(new TestTokenPrice(ha1Addr));

        vm.stopBroadcast();
        return ret;
    }
}
