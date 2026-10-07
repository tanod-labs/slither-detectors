// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IUniswapV2Pair {
    function getReserves() external view returns (uint112 reserve0, uint112 reserve1, uint32 blockTimestampLast);
}

interface IUniswapV3Pool {
    function slot0() external view returns (uint160 sqrtPriceX96, int24 tick, uint16 observationIndex,
        uint16 observationCardinality, uint16 observationCardinalityNext, uint8 feeProtocol, bool unlocked);
}

contract Lending {
    IUniswapV2Pair public pair;
    IUniswapV3Pool public pool;
    mapping(address => uint256) public collateral;

    constructor(IUniswapV2Pair _pair, IUniswapV3Pool _pool) {
        pair = _pair;
        pool = _pool;
    }

    function collateralPrice() public view returns (uint256) {
        (uint112 r0, uint112 r1, ) = pair.getReserves();
        return uint256(r1) * 1e18 / uint256(r0);
    }

    function poolPrice() public view returns (uint256) {
        (uint160 sqrtPriceX96, , , , , , ) = pool.slot0();
        return uint256(sqrtPriceX96) * uint256(sqrtPriceX96) >> 192;
    }

    function maxBorrow(address user) external view returns (uint256) {
        return collateral[user] * collateralPrice() / 1e18 / 2;
    }
}
