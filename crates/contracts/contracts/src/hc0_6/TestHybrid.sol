// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.12;

//sample "receiver" contract, for testing "exec" from account.

//interface IHybridAccount {
//  function CallOffchain(bytes32, bytes memory) external returns (uint32, bytes memory);
//}
import "./HybridAccount.sol";

contract TestHybrid {
    mapping(address => uint256) public counters;

    address payable immutable demoAddr;
    
    constructor(address payable _demoAddr) {
      demoAddr = _demoAddr;
    }

    function count(uint32 a, uint32 b) public {
       HybridAccount HA = HybridAccount(demoAddr);
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

    event CalledFrom(address sender);

    //helper method to waste gas
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
        HybridAccount HA = HybridAccount(payable(demoAddr));
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
