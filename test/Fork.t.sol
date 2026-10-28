// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;
import "forge-std/Test.sol";
import {StealthPay} from "../src/StealthPay.sol";
interface IERC20Like { function balanceOf(address) external view returns (uint256); function approve(address, uint256) external returns (bool); }

/// Real chains: the shared ERC-5564 Announcer. Run: BASE_RPC=<url> forge test --match-contract Fork
contract ForkTest is Test {
    address constant ANNOUNCER = 0x55649E01B5Df198D18D95b5cc5051630cfD45564;
    address constant USDC = 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913;
    event Announcement(uint256 indexed schemeId, address indexed stealthAddress, address indexed caller, bytes ephemeralPubKey, bytes metadata);
    function test_real_announcer_on_base() public {
        vm.createSelectFork(vm.envString("BASE_RPC"));
        StealthPay pay = new StealthPay(ANNOUNCER);
        address payer = address(0xA11CE); address stealth = address(uint160(uint256(keccak256("fresh stealth"))));
        deal(USDC, payer, 100e6);
        bytes memory key = hex"02" hex"1111111111111111111111111111111111111111111111111111111111111111";
        vm.startPrank(payer);
        IERC20Like(USDC).approve(address(pay), 100e6);
        vm.expectEmit(true, true, true, true, ANNOUNCER);
        emit Announcement(1, stealth, address(pay), key, abi.encodePacked(bytes1(0x7f), bytes4(0xa9059cbb), USDC, uint256(42e6)));
        pay.payToken(USDC, 42e6, stealth, key, 0x7f);
        vm.stopPrank();
        assertEq(IERC20Like(USDC).balanceOf(stealth), 42e6);
        assertEq(IERC20Like(USDC).balanceOf(address(pay)), 0);
    }
    /// Real Robinhood Chain (4663): same Announcer address and bytecode, USDG (EIP-3009, 6 decimals). Run: RH_RPC=<url> forge test --match-contract Fork
    address constant USDG = 0x5fc5360D0400a0Fd4f2af552ADD042D716F1d168;
    function test_real_announcer_on_robinhood() public {
        vm.createSelectFork(vm.envString("RH_RPC"));
        assertEq(block.chainid, 4663);
        StealthPay pay = new StealthPay(ANNOUNCER);
        address payer = address(0xA11CE); address stealth = address(uint160(uint256(keccak256("fresh stealth rh"))));
        deal(USDG, payer, 100e6);
        bytes memory key = hex"03" hex"2222222222222222222222222222222222222222222222222222222222222222";
        vm.startPrank(payer);
        IERC20Like(USDG).approve(address(pay), 100e6);
        vm.expectEmit(true, true, true, true, ANNOUNCER);
        emit Announcement(1, stealth, address(pay), key, abi.encodePacked(bytes1(0x2a), bytes4(0xa9059cbb), USDG, uint256(42e6)));
        pay.payToken(USDG, 42e6, stealth, key, 0x2a);
        vm.stopPrank();
        assertEq(IERC20Like(USDG).balanceOf(stealth), 42e6);
        assertEq(IERC20Like(USDG).balanceOf(address(pay)), 0);
    }
}
