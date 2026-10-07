// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function approve(address spender, uint256 amount) external returns (bool);
}

contract Escrow {
    IERC20 public immutable token;
    mapping(address => uint256) public deposits;

    constructor(IERC20 _token) {
        token = _token;
    }

    function deposit(uint256 amount) external {
        // return value ignored: a token that returns false is credited anyway
        token.transferFrom(msg.sender, address(this), amount);
        deposits[msg.sender] += amount;
    }

    function withdraw(uint256 amount) external {
        deposits[msg.sender] -= amount;
        // checked, but reverts for tokens that return nothing (USDT)
        require(token.transfer(msg.sender, amount), "transfer failed");
    }
}
