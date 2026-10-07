// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IUniswapV2Router {
    function swapExactTokensForTokens(uint256 amountIn, uint256 amountOutMin, address[] calldata path,
        address to, uint256 deadline) external returns (uint256[] memory amounts);
}

interface ISwapRouter {
    struct ExactInputSingleParams {
        address tokenIn;
        address tokenOut;
        uint24 fee;
        address recipient;
        uint256 deadline;
        uint256 amountIn;
        uint256 amountOutMinimum;
        uint160 sqrtPriceLimitX96;
    }
    function exactInputSingle(ExactInputSingleParams calldata params) external payable returns (uint256 amountOut);
}

contract Harvester {
    IUniswapV2Router public routerV2;
    ISwapRouter public routerV3;
    address public reward;
    address public want;

    constructor(IUniswapV2Router r2, ISwapRouter r3, address _reward, address _want) {
        routerV2 = r2;
        routerV3 = r3;
        reward = _reward;
        want = _want;
    }

    function harvest(uint256 amount, uint256 deadline) external {
        address[] memory path = new address[](2);
        path[0] = reward;
        path[1] = want;
        routerV2.swapExactTokensForTokens(amount, 0, path, address(this), deadline);
    }

    function harvestV3(uint256 amount, uint256 deadline) external returns (uint256) {
        return routerV3.exactInputSingle(ISwapRouter.ExactInputSingleParams({
            tokenIn: reward,
            tokenOut: want,
            fee: 3000,
            recipient: address(this),
            deadline: deadline,
            amountIn: amount,
            amountOutMinimum: 0,
            sqrtPriceLimitX96: 0
        }));
    }
}
