// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Script, console} from "forge-std/Script.sol";
import {StealthPay} from "../src/StealthPay.sol";

/// @notice Deploys StealthPay v3 (constructor: announcer, token).
/// Env (all required unless noted):
///   ANNOUNCER        ERC-5564 announcer (0x55649E01B5Df198D18D95b5cc5051630cfD45564 on Base and Robinhood Chain)
///   TOKEN            the one token of this deployment (USDC on Base, USDG on Robinhood Chain)
///   EXPECT_CHAIN_ID  8453 or 4663: refuses to run against any other chain (wrong --rpc-url protection)
///   DEPLOYER_KEY     optional: private key read from env, never from argv. Unset = simulation with `--sender <addr>`.
/// Simulate:  forge script script/DeployStealthPay.s.sol --fork-url $RPC --sender 0x<any funded addr>      (no --broadcast: nothing is sent)
/// Broadcast: set -a; . /path/deployer.env; set +a; forge script ... --rpc-url $RPC --broadcast
contract DeployStealthPay is Script {
    function run() external returns (StealthPay pay) {
        address announcer = vm.envAddress("ANNOUNCER");
        address token = vm.envAddress("TOKEN");
        uint256 expect = vm.envUint("EXPECT_CHAIN_ID");
        require(block.chainid == expect, "DeployStealthPay: wrong chain id");
        require(announcer.code.length > 0, "DeployStealthPay: no code at ANNOUNCER");
        require(token.code.length > 0, "DeployStealthPay: no code at TOKEN");
        uint256 pk = vm.envOr("DEPLOYER_KEY", uint256(0));
        if (pk != 0) vm.startBroadcast(pk); else vm.startBroadcast();
        pay = new StealthPay(announcer, token);
        vm.stopBroadcast();
        require(address(pay.ANNOUNCER()) == announcer && pay.TOKEN() == token, "DeployStealthPay: constructor mismatch");
        console.log("chainid", block.chainid);
        console.log("StealthPay deployed at", address(pay));
        console.log("announcer", announcer);
        console.log("token", token);
    }
}
