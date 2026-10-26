// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;
import "forge-std/Test.sol";
import {StealthPay} from "../src/StealthPay.sol";

contract MockAnnouncer {
    uint256 public n; uint256 public lastScheme; address public lastStealth; bytes public lastKey; bytes public lastMeta; address public lastCaller;
    function announce(uint256 s, address a, bytes calldata k, bytes calldata m) external { n++; lastScheme = s; lastStealth = a; lastKey = k; lastMeta = m; lastCaller = msg.sender; }
}
contract Tok {
    mapping(address => uint256) public balanceOf; mapping(address => mapping(address => uint256)) public allowance;
    function mint(address t, uint256 a) external { balanceOf[t] += a; }
    function approve(address s, uint256 a) external returns (bool) { allowance[msg.sender][s] = a; return true; }
    function transferFrom(address f, address t, uint256 a) external returns (bool) {
        require(allowance[f][msg.sender] >= a, "allowance"); allowance[f][msg.sender] -= a;
        require(balanceOf[f] >= a, "balance"); balanceOf[f] -= a; balanceOf[t] += a; return true;
    }
}
contract Reenter { StealthPay p; constructor(StealthPay _p) { p = _p; } receive() external payable { p.payETH{value: 1}(address(0xDEAD), hex"02" hex"0000000000000000000000000000000000000000000000000000000000000001", 0x00); } }

contract StealthPayTest is Test {
    MockAnnouncer ann; StealthPay pay; Tok tok; address payer = address(0xA11CE);
    bytes key = hex"02" hex"1111111111111111111111111111111111111111111111111111111111111111";
    function setUp() public {
        ann = new MockAnnouncer(); pay = new StealthPay(address(ann)); tok = new Tok();
        tok.mint(payer, 1_000e6); vm.prank(payer); tok.approve(address(pay), type(uint256).max); vm.deal(payer, 10 ether);
    }
    function test_token_goes_straight_to_stealth_and_is_announced() public {
        address s = address(0xBEEF);
        vm.prank(payer); pay.payToken(address(tok), 250e6, s, key, 0xAB);
        assertEq(tok.balanceOf(s), 250e6); assertEq(tok.balanceOf(address(pay)), 0);
        assertEq(ann.n(), 1); assertEq(ann.lastScheme(), 1); assertEq(ann.lastStealth(), s); assertEq(ann.lastCaller(), address(pay));
        assertEq(ann.lastKey(), key);
        assertEq(ann.lastMeta(), abi.encodePacked(bytes1(0xAB), bytes4(0xa9059cbb), address(tok), uint256(250e6)));
        assertEq(ann.lastMeta().length, 57, "ERC-5564 metadata layout: 1 + 4 + 20 + 32");
    }
    function test_eth_goes_straight_to_stealth_and_is_announced() public {
        address s = address(0xBEEF);
        vm.prank(payer); pay.payETH{value: 1 ether}(s, key, 0x01);
        assertEq(s.balance, 1 ether); assertEq(address(pay).balance, 0);
        assertEq(ann.lastMeta(), abi.encodePacked(bytes1(0x01), bytes4(0xeeeeeeee), pay.ETH(), uint256(1 ether)));
    }
    function test_same_stealth_address_cannot_be_paid_twice_here() public {
        address s = address(0xBEEF);
        vm.startPrank(payer);
        pay.payToken(address(tok), 1e6, s, key, 0x00);
        vm.expectRevert(abi.encodeWithSelector(StealthPay.NotFresh.selector, s));
        pay.payToken(address(tok), 1e6, s, key, 0x00);
        vm.expectRevert(abi.encodeWithSelector(StealthPay.NotFresh.selector, s));
        pay.payETH{value: 1}(s, key, 0x00);
        vm.stopPrank();
    }
    function test_contract_address_is_not_a_stealth_address() public {
        vm.prank(payer); vm.expectRevert(abi.encodeWithSelector(StealthPay.NotFresh.selector, address(tok)));
        pay.payToken(address(tok), 1e6, address(tok), key, 0x00);
    }
    function test_ephemeral_key_must_be_33_byte_compressed() public {
        vm.startPrank(payer);
        vm.expectRevert(StealthPay.BadKey.selector); pay.payToken(address(tok), 1e6, address(0xBEEF), hex"04" hex"11", 0x00);
        vm.expectRevert(StealthPay.BadKey.selector); pay.payToken(address(tok), 1e6, address(0xBEEF), hex"02", 0x00);
        vm.stopPrank();
    }
    function test_zero_amount_reverts() public {
        vm.startPrank(payer);
        vm.expectRevert(StealthPay.ZeroAmount.selector); pay.payToken(address(tok), 0, address(0xBEEF), key, 0x00);
        vm.expectRevert(StealthPay.ZeroAmount.selector); pay.payETH{value: 0}(address(0xBEEF), key, 0x00);
        vm.stopPrank();
    }
    function test_failed_transfer_reverts_and_announces_nothing() public {
        address poor = address(0xB0B); vm.prank(poor); tok.approve(address(pay), 1e6);
        vm.prank(poor); vm.expectRevert(); pay.payToken(address(tok), 1e6, address(0xBEEF), key, 0x00);
        assertEq(ann.n(), 0);
    }
    function test_eth_receiver_that_reenters_is_refused() public {
        Reenter r = new Reenter(pay);
        // a contract receiver is already refused as not fresh -- the lock is a second line
        vm.prank(payer); vm.expectRevert(abi.encodeWithSelector(StealthPay.NotFresh.selector, address(r)));
        pay.payETH{value: 1 ether}(address(r), key, 0x00);
    }
}
