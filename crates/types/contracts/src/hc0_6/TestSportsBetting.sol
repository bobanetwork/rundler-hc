// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./HybridAccount.sol";

contract SportsBetting {
    address payable immutable helperAddr;

    constructor(address payable _helperAddr) {
        helperAddr = _helperAddr;
    }

    struct Bet {
        address bettor;
        uint256 amount;
        uint256 outcome; // 1 for Team A win, 2 for Team B win, 3 for Draw
        bool settled;
    }

    struct Game {
        uint256 gameId;
        bool exists;
    }

    mapping(uint256 => Game) public games;
    mapping(uint256 => Bet[]) public bets;
    mapping(uint256 => uint256) public gameScores; // 1 for Team A win, 2 for Team B win, 3 for Draw

    event GameCreated(uint256 indexed gameId);
    event BetPlaced(
        address indexed bettor,
        uint256 indexed gameId,
        uint256 amount,
        uint256 outcome
    );
    event BetSettled(
        address indexed bettor,
        uint256 indexed gameId,
        uint256 outcome,
        uint256 winnings
    );
    event GameScoreUpdated(uint256 indexed gameId, uint256 score);

    function createGame(uint256 gameId) external returns (uint256) {
        games[gameId] = Game({gameId: gameId, exists: true});

        emit GameCreated(gameId);
        return gameId;
    }

    function placeBet(uint256 _gameId, uint256 _outcome) external payable {
        require(msg.value > 0, "Bet amount must be greater than zero");
        require(_outcome >= 1 && _outcome <= 3, "Invalid outcome");
        require(games[_gameId].exists, "Game does not exist");

        bets[_gameId].push(
            Bet({
                bettor: msg.sender,
                amount: msg.value,
                outcome: _outcome,
                settled: false
            })
        );

        emit BetPlaced(msg.sender, _gameId, msg.value, _outcome);
    }

    function settleBet(uint256 _gameId) external {
        require(games[_gameId].exists, "Game does not exist");

        uint256 actualOutcome = updateGameScore(_gameId);
        //uint256 actualOutcome = gameScores[_gameId];

        for (uint256 i = 0; i < bets[_gameId].length; i++) {
            Bet storage bet = bets[_gameId][i];
            if (!bet.settled) {
                if (bet.outcome == actualOutcome) {
                    uint256 winnings = bet.amount * 2; // Here you could fetch the winning ratio from offchain to calculate the user's win.
                    payable(bet.bettor).transfer(winnings);
                    emit BetSettled(
                        bet.bettor,
                        _gameId,
                        actualOutcome,
                        winnings
                    );
                }
                bet.settled = true;
            }
        }
    }

    function updateGameScore(uint256 _gameId) internal returns (uint256) {
        require(games[_gameId].exists, "Game does not exist");

        HybridAccount ha = HybridAccount(helperAddr);

        bytes memory req = abi.encodeWithSignature(
            "get_score(uint256)",
            _gameId
        );
        bytes32 userKey = bytes32(abi.encode(msg.sender));
        (uint32 error, bytes memory ret) = ha.CallOffchain(userKey, req);

        if (error != 0) {
            revert(string(ret));
        }

        uint256 result;
        (result) = abi.decode(ret, (uint256));
        gameScores[_gameId] = result;
        emit GameScoreUpdated(_gameId, result);
        return result;
    }
}
