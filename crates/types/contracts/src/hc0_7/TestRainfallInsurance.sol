// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.12;
import "./HybridAccount.sol";

contract RainfallInsurance {
    struct Policy {
        address policyholder;
        uint256 premium;
        uint256 payoutAmount;
        uint256 triggerRainfall;
        string city;
        uint256 timestamp;
        PolicyState state;
    }

    enum PolicyState {
        Active,
        Expired,
        Claimed
    }

    struct Rainfall {
        uint256 rainfallInMm;
        uint256 updatedAt;
    }

    mapping(uint256 => Policy) public policies;
    mapping(string => Rainfall) public currentRainfall;
    uint256 public constant MULTIPLIER = 3;
    address payable immutable helperAddr;

    uint256 private nonce;

    event PolicyCreated(uint256 indexed policyId, address indexed policyholder, string city, uint256 premium, uint256 payoutAmount);


    constructor(address payable _helperAddr) {
        helperAddr = _helperAddr;
    }

    function generatePolicyId(address policyHolder, string memory city) internal returns (uint256) {
        nonce++;
        return uint256(keccak256(abi.encodePacked(policyHolder, city, block.timestamp, nonce)));
    }

    function buyInsurance(
        uint256 triggerRainfall,
        string memory city
    ) public payable returns (uint256){
        require(msg.value > 0, "Premium must be greater than zero");
        uint256 payoutAmount = msg.value * MULTIPLIER;
        uint256 policyId = generatePolicyId(msg.sender, city);

        policies[policyId] = Policy(
            msg.sender,
            msg.value,
            payoutAmount,
            triggerRainfall,
            city,
            block.timestamp,
            PolicyState.Active
        );

        emit PolicyCreated(policyId, msg.sender, city, msg.value, payoutAmount);
    }

    function updateRainfall(
        string memory city
    ) internal returns (Rainfall storage) {
        HybridAccount ha = HybridAccount(helperAddr);

        bytes memory req = abi.encodeWithSignature(
            "get_rainfall(string)",
            city
        );
        bytes32 userKey = bytes32(abi.encode(msg.sender));
        (uint32 error, bytes memory ret) = ha.CallOffchain(userKey, req);

        if (error != 0) {
            revert(string(ret));
        }

        uint256 rainfallInMm;
        (rainfallInMm) = abi.decode(ret, (uint256));
        currentRainfall[city] = Rainfall(rainfallInMm, block.timestamp);

        return currentRainfall[city];
    }

    function checkAndPayout(uint256 policyId) public {
        Policy storage policy = policies[policyId];
        require(policy.state == PolicyState.Active, "Policy is not active");

        if (policy.timestamp + 365 days < block.timestamp) {
            policy.state = PolicyState.Expired;
            revert("Policy expired");
        }

        Rainfall storage rainfall = currentRainfall[policy.city];

        if (
            rainfall.updatedAt == 0 ||
            rainfall.updatedAt + 24 hours < block.timestamp
        ) {
            rainfall = updateRainfall(policy.city);
        }


        require(
            rainfall.rainfallInMm <= policy.triggerRainfall,
            "Trigger condition not met"
        );

        policy.state = PolicyState.Claimed;
        payable(policy.policyholder).transfer(policy.payoutAmount);
    }
}
