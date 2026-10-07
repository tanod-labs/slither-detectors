// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface AggregatorV3Interface {
    function latestRoundData() external view returns (uint80 roundId, int256 answer, uint256 startedAt,
        uint256 updatedAt, uint80 answeredInRound);
}

contract PriceConsumer {
    AggregatorV3Interface public feed;

    constructor(AggregatorV3Interface _feed) {
        feed = _feed;
    }

    function getPrice() public view returns (uint256) {
        (, int256 answer, , , ) = feed.latestRoundData();
        return uint256(answer);
    }
}
