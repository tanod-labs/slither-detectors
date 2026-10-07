// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Staking {
    struct Position {
        uint128 amount;
        uint64 lockedUntil;
    }

    mapping(address => Position) public positions;

    function stake(uint256 amount, uint256 lockDuration) external {
        Position storage p = positions[msg.sender];
        p.amount += uint128(amount);
        p.lockedUntil = uint64(block.timestamp + lockDuration);
    }
}
