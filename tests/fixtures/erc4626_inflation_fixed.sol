// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function balanceOf(address account) external view returns (uint256);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

contract SimpleVault {
    IERC20 public immutable asset;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;

    constructor(IERC20 _asset) {
        asset = _asset;
    }

    function _decimalsOffset() internal pure returns (uint8) {
        return 6;
    }

    function totalAssets() public view returns (uint256) {
        return asset.balanceOf(address(this));
    }

    function convertToShares(uint256 assets) public view returns (uint256) {
        // virtual shares and a virtual asset make the first-depositor donation attack unprofitable
        return assets * (totalSupply + 10 ** _decimalsOffset()) / (totalAssets() + 1);
    }

    function deposit(uint256 assets, address receiver) external returns (uint256 shares) {
        shares = convertToShares(assets);
        require(asset.transferFrom(msg.sender, address(this), assets), "transfer");
        totalSupply += shares;
        balanceOf[receiver] += shares;
    }
}
