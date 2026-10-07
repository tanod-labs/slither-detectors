// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IUniswapV2Router {
    function swapExactTokensForTokens(uint256 amountIn, uint256 amountOutMin, address[] calldata path,
        address to, uint256 deadline) external returns (uint256[] memory amounts);
    function addLiquidity(address tokenA, address tokenB, uint256 amountADesired, uint256 amountBDesired,
        uint256 amountAMin, uint256 amountBMin, address to, uint256 deadline)
        external returns (uint256 amountA, uint256 amountB, uint256 liquidity);
}

contract Zap {
    IUniswapV2Router public router;

    constructor(IUniswapV2Router _router) {
        router = _router;
    }

    function swap(address[] calldata path, uint256 amountIn, uint256 minOut) external {
        router.swapExactTokensForTokens(amountIn, minOut, path, msg.sender, block.timestamp);
    }

    function addLiq(address a, address b, uint256 amtA, uint256 amtB, uint256 minA, uint256 minB) external {
        router.addLiquidity(a, b, amtA, amtB, minA, minB, msg.sender, block.timestamp + 300);
    }
}
