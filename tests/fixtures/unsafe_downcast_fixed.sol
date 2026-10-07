// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

library SafeCast {
    function toUint128(uint256 value) internal pure returns (uint128) {
        require(value <= type(uint128).max, "SafeCast: overflow");
        return uint128(value);
    }

    function toUint64(uint256 value) internal pure returns (uint64) {
        require(value <= type(uint64).max, "SafeCast: overflow");
        return uint64(value);
    }
}

contract Staking {
    using SafeCast for uint256;

    struct Position {
        uint128 amount;
        uint64 lockedUntil;
    }

    mapping(address => Position) public positions;

    function stake(uint256 amount, uint256 lockDuration) external {
        Position storage p = positions[msg.sender];
        p.amount += amount.toUint128();
        p.lockedUntil = (block.timestamp + lockDuration).toUint64();
    }
}
