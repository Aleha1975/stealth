// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;
import "forge-std/Test.sol";
import {StealthPay} from "../src/StealthPay.sol";
interface IUSDG { function DOMAIN_SEPARATOR() external view returns (bytes32); }
interface IERC20Like { function balanceOf(address) external view returns (uint256); function approve(address, uint256) external returns (bool); }

/// Real chains: the shared ERC-5564 Announcer. Run: BASE_RPC=<url> forge test --match-contract Fork
contract ForkTest is Test {
    address constant ANNOUNCER = 0x55649E01B5Df198D18D95b5cc5051630cfD45564;
    address constant USDC = 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913;
    event Announcement(uint256 indexed schemeId, address indexed stealthAddress, address indexed caller, bytes ephemeralPubKey, bytes metadata);
    function test_real_announcer_on_base() public {
        vm.createSelectFork(vm.envString("BASE_RPC"));
        StealthPay pay = new StealthPay(ANNOUNCER, USDC);
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
        StealthPay pay = new StealthPay(ANNOUNCER, USDG);
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

    // ---- payWithAuthorization on real USDG (Robinhood Chain) ----
    bytes32 constant RECEIVE_TYPEHASH = 0xd099cc98ef71107a616c4f0f941f04c322d8e254fe26b3c6668db87aae413de8;
    uint256 constant PAYER_PK = 0xBADA55;
    address constant RELAYER = address(0x7E1A);
    address constant SUBMITTER = address(0x5B17);
    bytes constant RH_KEY = hex"03" hex"2222222222222222222222222222222222222222222222222222222222222222";

    function _rhSign(StealthPay pay, address stealth, uint256 amount, uint256 fee)
        internal view returns (StealthPay.Authorization memory a)
    {
        bytes32 nonce = pay.paymentNonce(USDG, stealth, RH_KEY, 0x2a, fee, RELAYER);
        a.from = vm.addr(PAYER_PK); a.validAfter = 0; a.validBefore = block.timestamp + 1 hours;
        bytes32 inner = keccak256(abi.encode(RECEIVE_TYPEHASH, a.from, address(pay), amount, a.validAfter, a.validBefore, nonce));
        (a.v, a.r, a.s) = vm.sign(PAYER_PK, keccak256(abi.encodePacked("\x19\x01", IUSDG(USDG).DOMAIN_SEPARATOR(), inner)));
    }

    function test_pay_with_authorization_on_robinhood_usdg() public {
        vm.createSelectFork(vm.envString("RH_RPC"));
        assertEq(block.chainid, 4663);
        bytes32 computed = keccak256(abi.encode(keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"), keccak256("Global Dollar"), keccak256("1"), uint256(4663), USDG));
        assertEq(IUSDG(USDG).DOMAIN_SEPARATOR(), computed, "domain matches Global Dollar / 1 / 4663");

        StealthPay pay = new StealthPay(ANNOUNCER, USDG);
        address payer = vm.addr(PAYER_PK);
        address stealth = address(uint160(uint256(keccak256("fresh stealth rh auth"))));
        deal(USDG, payer, 100e6);
        uint256 fee = 0.05e6;
        StealthPay.Authorization memory a = _rhSign(pay, stealth, 10e6, fee);

        // negative: the same signature aimed at another stealth address is rejected by the token (nonce binds it)
        address other = address(uint160(uint256(keccak256("other stealth rh auth"))));
        vm.prank(SUBMITTER);
        vm.expectRevert();
        pay.payWithAuthorization(USDG, 10e6, other, RH_KEY, 0x2a, fee, RELAYER, a);
        assertEq(IERC20Like(USDG).balanceOf(payer), 100e6, "nothing moved");

        vm.expectEmit(true, true, true, true, ANNOUNCER);
        emit Announcement(1, stealth, address(pay), RH_KEY, abi.encodePacked(bytes1(0x2a), bytes4(0xa9059cbb), USDG, uint256(10e6 - fee)));
        vm.prank(SUBMITTER);
        pay.payWithAuthorization(USDG, 10e6, stealth, RH_KEY, 0x2a, fee, RELAYER, a);

        assertEq(IERC20Like(USDG).balanceOf(stealth), 10e6 - fee, "stealth gets net");
        assertEq(IERC20Like(USDG).balanceOf(RELAYER), fee, "relayer gets fee");
        assertEq(IERC20Like(USDG).balanceOf(address(pay)), 0, "contract keeps nothing");
        assertEq(IERC20Like(USDG).balanceOf(payer), 90e6, "payer debited amount");
        assertEq(IERC20Like(USDG).balanceOf(SUBMITTER), 0);
    }
}
