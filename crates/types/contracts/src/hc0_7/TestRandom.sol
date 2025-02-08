// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import "./HybridAccount.sol";
import "../../lib/chainlink/VRF.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";

contract TestRandom is VRF, ReentrancyGuard, UUPSUpgradeable, Initializable  {
    using SafeERC20 for IERC20;

    // Constraints on the block distance between request and reveal
    uint256 constant MIN_DISTANCE = 2;
    uint256 constant MAX_DISTANCE = 255;

    address payable immutable hcAccount;
    IERC20 immutable bobaToken;

    address public owner;

    // Payment is currently structured to collect a fixed token fee
    // per request, and to pay a fixed amount to the HybridAccount
    // prior to retrieving the offchain response. These amounts may
    // be set to zero. The payPerCall mechanism is a workaround for
    // a HybridAccount which is not configured to pull payments from
    // its callers.
    uint256 feePerCall;
    uint256 payPerCall;

    event RandomRequest(bytes32 indexed requestId, address indexed clientAddress);
    event RandomResult (bytes32 indexed requestId, uint256 indexed result);
    event StaleRequestRemoved(bytes32 indexed requestId);
    event TokenWithdrawal(address withdrawTo, uint256 amount);
    event KeyHashChanged(bytes32 indexed newKeyHash);

    uint256 randIndex;

    // Key to verify VRF responses.
    bytes32 randomKeyHash;

    // Store the parameters of a random request
    struct randRequest {
        uint256 blockNumber;
        bytes32 pubkeyHash;
        bytes32 seed;
        bytes32 clientCommitment;
        address clientAddress;
    }

    // Pending requests
    mapping(bytes32=>randRequest) randRequests;

    modifier onlyOwner() {
        _onlyOwner();
        _;
    }

    function _onlyOwner() internal view {
        require(msg.sender == owner || msg.sender == address(this), "only owner");
    }

    //constructor
    constructor(address payable _hcAccount, address _bobaToken) {
        hcAccount = _hcAccount;
        bobaToken = IERC20(_bobaToken);
        randIndex = 1;
    }

    // Set the initial owner
    function initialize(address _owner, bytes32 _randomKeyHash) public virtual initializer {
        owner = _owner;
        randomKeyHash = _randomKeyHash;
    }

    // Allow upgrade through UUPSUpgradeable
    function _authorizeUpgrade(address newImplementation) internal view override {
        (newImplementation);
        _onlyOwner();
    }

    // Replaces the public key hash. Does not affect existing requests.
    function newKeyHash (bytes32 newHash) public onlyOwner {
        randomKeyHash = newHash;
        emit KeyHashChanged(newHash);
    }

    // Set the Boba token prices per call
    function SetFees(uint256 newFee, uint256 newPay) public onlyOwner {
        feePerCall = newFee;
        payPerCall = newPay;
    }

    // Registers a jointly generated VRF request to be satisfied in a later block.
    // In this protocol the client provides its own random value which is XOR-ed
    // into the final result when revealed. The request contains a hash of the
    // client's random value.
    function requestJointRandomWord(bytes32 clientHash) public nonReentrant returns (bytes32 requestId) {
        if (feePerCall > 0) {
            bobaToken.safeTransferFrom(msg.sender, address(this), feePerCall);
        }

        // TODO: Collect payment in Boba token or other mechanism, cost TBD
        require(randomKeyHash != bytes32(0), "Public key hash not registered");

        randIndex += 1;
        requestId = keccak256(abi.encode(randIndex, msg.sender));

        randRequest memory req;
        req.pubkeyHash = randomKeyHash;
        req.blockNumber = block.number;
        req.clientCommitment = clientHash;
        req.clientAddress = msg.sender;
        req.seed = keccak256(abi.encodePacked(randIndex, msg.sender, req.pubkeyHash, clientHash));

        randRequests[requestId] = req;

        emit RandomRequest(requestId, msg.sender);
    }

    // Registers a server-only VRF request to be satisfied in a later block.
    function requestRandomWord() public returns (bytes32 requestId) {
        requestJointRandomWord(bytes32(0));
    }

    // Needed to convert an in-memory Proof into calldata
    function vrfWrapper(VRF.Proof calldata proof, uint256 seed) public view returns (uint256) {
        return _randomValueFromVRFProof(proof, seed);
    }

    // Calls offchain VRF to satisfy a previous request. Verifies the proof using code
    // copied from Chainlink, then returns the computed result.
    function revealJointRandomWord(bytes32 requestId, uint256 clientRandom) public nonReentrant returns (uint256 result)
    {
        HybridAccount HA = HybridAccount(hcAccount);
        bytes32 userKey = bytes32(abi.encode(msg.sender, requestId));

        randRequest memory req = randRequests[requestId];
        delete randRequests[requestId];
        require (req.blockNumber != 0, "Invalid requestId");
        require (req.blockNumber + MIN_DISTANCE <= block.number, "Insufficient block distance from request");
        require (req.blockNumber + MAX_DISTANCE > block.number, "Stale request");
        require (req.clientAddress == msg.sender, "Unauthorized caller");

        if (req.clientCommitment != bytes32(0)) {
            require(req.clientCommitment == keccak256(abi.encode(clientRandom)), "clientRandom does not match commitment");
        } else {
            require(clientRandom == 0, "clientRandom supplied without commitment");
        }

        bytes memory hc_req = abi.encodeWithSignature("random(uint256,bytes32)", req.blockNumber, req.seed);
        if (payPerCall > 0) {
            bobaToken.safeTransfer(address(HA), payPerCall);
        }
        (uint32 error, bytes memory ret) = HA.CallOffchain(userKey, hc_req);

        if (error != 0) {
          revert(string(ret));
        }

        Proof memory pp = abi.decode(ret,(Proof));
        bytes32 keyHash = keccak256(abi.encode(pp.pk[0],pp.pk[1]));
        require(keyHash == req.pubkeyHash, "Invalid public key");

        bytes32 blockHash = blockhash(req.blockNumber);
        uint256 actualSeed = uint256(keccak256(abi.encodePacked(pp.seed, blockHash)));
        uint256 serverResult = this.vrfWrapper(pp, actualSeed);

        result = serverResult ^ clientRandom;

        emit RandomResult(requestId, result);
    }

    // Wrapper for the server-only protocol
    function revealRandomWord(bytes32 requestId) public returns (uint256 result)
    {
        return revealJointRandomWord(requestId, 0);
    }

    // Administrative function to remove requests which were not satisfied
    // and are no longer valid due to block distance from the request.
    // Although not strictly required, this does provide a mechanism to reduce
    // wasted storage space on the chain.
    function RemoveStaleRequests(bytes32[] calldata requestIds) public onlyOwner {
        uint256 i;
        for (i=0; i < requestIds.length; i++) {
            bytes32 req_id = requestIds[i];
            require (randRequests[req_id].blockNumber + MAX_DISTANCE < block.number, "Request is not stale");
            delete randRequests[req_id];
            emit StaleRequestRemoved(req_id);
        }
    }

    // Allow the owner to withdraw tokens
    function WithdrawTokens(uint256 amount, address withdrawTo) public onlyOwner nonReentrant {
        emit TokenWithdrawal(withdrawTo, amount);
        bobaToken.safeTransfer(withdrawTo, amount);
    }
}
