// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface ITwapOracle {
    function consult(address token, uint32 secondsAgo) external view returns (uint256 price);
}

contract Lending {
    ITwapOracle public oracle;
    address public collateralToken;
    mapping(address => uint256) public collateral;

    constructor(ITwapOracle _oracle, address _token) {
        oracle = _oracle;
        collateralToken = _token;
    }

    function collateralPrice() public view returns (uint256) {
        return oracle.consult(collateralToken, 1800);
    }

    function maxBorrow(address user) external view returns (uint256) {
        return collateral[user] * collateralPrice() / 1e18 / 2;
    }
}
