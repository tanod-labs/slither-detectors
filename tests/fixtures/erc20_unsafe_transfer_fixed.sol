// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

library SafeERC20 {
    function safeTransfer(IERC20 token, address to, uint256 amount) internal {
        _call(token, abi.encodeWithSelector(token.transfer.selector, to, amount));
    }

    function safeTransferFrom(IERC20 token, address from, address to, uint256 amount) internal {
        _call(token, abi.encodeWithSelector(token.transferFrom.selector, from, to, amount));
    }

    function _call(IERC20 token, bytes memory data) private {
        (bool ok, bytes memory ret) = address(token).call(data);
        require(ok && (ret.length == 0 || abi.decode(ret, (bool))), "SafeERC20: failed");
    }
}

contract Escrow {
    using SafeERC20 for IERC20;

    IERC20 public immutable token;
    mapping(address => uint256) public deposits;

    constructor(IERC20 _token) {
        token = _token;
    }

    function deposit(uint256 amount) external {
        token.safeTransferFrom(msg.sender, address(this), amount);
        deposits[msg.sender] += amount;
    }

    function withdraw(uint256 amount) external {
        deposits[msg.sender] -= amount;
        token.safeTransfer(msg.sender, amount);
    }
}
