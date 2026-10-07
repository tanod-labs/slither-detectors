// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Voucher {
    address public signer;
    mapping(address => uint256) public nonces;
    mapping(address => uint256) public credits;

    function setSigner(address s) external {
        require(signer == address(0), "set");
        signer = s;
    }

    function redeem(uint256 amount, uint8 v, bytes32 r, bytes32 s) external {
        bytes32 digest = keccak256(abi.encode(msg.sender, amount, nonces[msg.sender]++, block.chainid, address(this)));
        address recovered = ecrecover(digest, v, r, s);
        require(recovered != address(0), "invalid sig");
        require(recovered == signer, "bad sig");
        credits[msg.sender] += amount;
    }
}
