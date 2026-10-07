// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Airdrop {
    address public immutable signer;
    mapping(address => uint256) public balance;
    mapping(address => uint256) public nonces;

    constructor(address _signer) {
        require(_signer != address(0), "zero");
        signer = _signer;
    }

    function _recover(bytes32 digest, uint8 v, bytes32 r, bytes32 s) internal pure returns (address a) {
        a = ecrecover(digest, v, r, s);
        require(a != address(0), "invalid sig");
    }

    function claim(uint256 amount, uint8 v, bytes32 r, bytes32 s) external {
        bytes32 digest = keccak256(abi.encode(block.chainid, address(this), msg.sender, amount, nonces[msg.sender]++));
        require(_recover(digest, v, r, s) == signer, "bad sig");
        balance[msg.sender] += amount;
    }
}
