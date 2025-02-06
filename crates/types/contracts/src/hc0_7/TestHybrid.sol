// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.23;

import "./HybridAccount.sol";
import "../../lib/chainlink/VRF.sol";

contract TestHybrid is VRF {
    mapping(address => uint256) public counters;

    address payable immutable hcAccount;

    event CalledFrom(address sender);

    event RandomRequest(bytes32 indexed requestId, address indexed clientAddress);
    event RandomResult (bytes32 indexed requestId, uint256 indexed result);

    uint256 randIndex;

    // Key to verify VRF responses.
    // TODO: add a mechanism to update key, or add/remove in a list
    bytes32 randomKeyHash;

    constructor(address payable _hcAccount, bytes32 _randomKeyHash) {
      hcAccount = _hcAccount;
      randIndex = 1;
      randomKeyHash = _randomKeyHash;
    }

    // helper method to waste gas
    // repeat - waste gas on writing storage in a loop
    // junk - dynamic buffer to stress the function size.
    mapping(uint256 => uint256) public xxx;
    uint256 public offset;

    function gasWaster(uint256 repeat, string calldata /*junk*/) external {
        for (uint256 i = 1; i <= repeat; i++) {
            offset++;
            xxx[offset] = i;
        }
    }

    struct randRequest {
        uint256 blockNumber;
        bytes32 pubkeyHash;
        bytes32 seed;
        bytes32 clientCommitment;
        address clientAddress;
    }

    mapping(bytes32=>randRequest) randRequests;

    // Registers a jointly generated VRF request to be satisfied in a later block.
    // In this protocol the client provides its own random value which is XOR-ed
    // into the final result when revealed. The request contains a hash of the
    // client's random value.
    function requestJointRandomWord(bytes32 clientHash) public returns (bytes32 requestId) {
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
    function revealJointRandomWord(bytes32 requestId, uint256 clientRandom) public returns (uint256 result)
    {
        HybridAccount HA = HybridAccount(hcAccount);
        bytes32 userKey = bytes32(abi.encode(msg.sender, requestId));

        randRequest memory req = randRequests[requestId];
        delete randRequests[requestId];
        require (req.blockNumber != 0, "Invalid requestId");
        require (req.blockNumber + 4 <= block.number, "Insufficient block distance from request");
        require (req.blockNumber + 1000 > block.number, "Stale request");
        require (req.clientAddress == msg.sender, "Unauthorized caller");

        if (req.clientCommitment != bytes32(0)) {
            require(req.clientCommitment == keccak256(abi.encode(clientRandom)), "clientRandom does not match commitment");
        } else {
            require(clientRandom == 0, "clientRandom supplied without commitment");
        }

        bytes memory hc_req = abi.encodeWithSignature("random(uint256,bytes32)", req.blockNumber, req.seed);
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

    function count(uint32 a, uint32 b) public {
       HybridAccount HA = HybridAccount(hcAccount);
       uint256 x;
       uint256 y;
       if (b == 0) {
           counters[msg.sender] = counters[msg.sender] + a;
	   return;
       }
       bytes memory req = abi.encodeWithSignature("addsub2(uint32,uint32)", a, b);
       bytes32 userKey = bytes32(abi.encode(msg.sender));
       (uint32 error, bytes memory ret) = HA.CallOffchain(userKey, req);

       if (error == 0) {
           (x,y) = abi.decode(ret,(uint256,uint256)); // x=(a+b), y=(a-b)

           this.gasWaster(x, "abcd1234");
           counters[msg.sender] = counters[msg.sender] + y;
       } else if (b >= 10) {
           revert(string(ret));
       } else if (error == 1) {
           counters[msg.sender] = counters[msg.sender] + 100;
       } else {
           //revert(string(ret));
           counters[msg.sender] = counters[msg.sender] + 1000;
       }
    }

    function countFail() public pure {
        revert("count failed");
    }

    function justemit() public {
        emit CalledFrom(msg.sender);
    }

    /* This example is a word-guessing game. The user picks a four-letter word as their guess,
       and pays for the number of entries they wish to purchase. This wager is added to a pool.
       The offchain provider generates a random array of words and returns it as a string[]. If
       the user's guess appears in the list returned from the server then they win the entire pool.

       A boolean flag allows the user to cheat by guaranteeing that the word "frog" will appear
       in the list.
    */
    event GameResult(address indexed caller,uint256 indexed win, uint256 indexed Pool);
    uint256 public constant EntryCost = 2 gwei;
    uint256 public Pool = 0;

    function wordGuess(string calldata myGuess, bool cheat) public payable {
        HybridAccount HA = HybridAccount(payable(hcAccount));
        uint256 entries = msg.value / EntryCost;
	require(entries > 0, "No entries purchased");
	require(entries <= 100, "Excess payment");
        Pool += msg.value;
	require(bytes(myGuess).length == 4, "Game uses 4-letter words");

        bytes memory req = abi.encodeWithSignature("ramble(uint256,bool)", entries, cheat);
        bytes32 userKey = bytes32(abi.encode(msg.sender));
        (uint32 error, bytes memory ret) = HA.CallOffchain(userKey, req);
        if (error != 0) {
            revert(string(ret));
	}

	uint256 win = 0;
	string[] memory words = abi.decode(ret,(string[]));

        for (uint256 i=0; i<words.length; i++) {
	    if (keccak256(bytes(words[i])) == keccak256(bytes(myGuess))) {
	        win = Pool;  // Safe if there's more than one match in the list
	    }
	}

	if (win == Pool) {
	    Pool = 0;
	    (bool sent,) = msg.sender.call{value: win}("");
	    require(sent, "Payment failed");
	}
	emit GameResult(msg.sender,win,Pool);
    }
}
