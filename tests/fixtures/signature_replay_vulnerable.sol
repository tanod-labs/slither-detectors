// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Airdrop {
    address public immutable signer;
    mapping(address => uint256) public balance;

    constructor(address _signer) {
        require(_signer != address(0), "zero");
        signer = _signer;
    }

    function _recover(bytes32 digest, uint8 v, bytes32 r, bytes32 s) internal pure returns (address a) {
        a = ecrecover(digest, v, r, s);
        require(a != address(0), "invalid sig");
    }

    // Neither a nonce nor the chain id is signed: the same signature can be replayed
    // any number of times, and on every chain where this contract is deployed.
    function claim(uint256 amount, uint8 v, bytes32 r, bytes32 s) external {
        bytes32 digest = keccak256(abi.encodePacked(msg.sender, amount));
        require(_recover(digest, v, r, s) == signer, "bad sig");
        balance[msg.sender] += amount;
    }
}
