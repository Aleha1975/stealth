// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;
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
contract Reenter { StealthPay p; constructor(StealthPay _p) { p = _p; } receive() external payable { p.payETH{value: 1}(address(0xDEAD00), hex"02" hex"0000000000000000000000000000000000000000000000000000000000000001", 0x00); } }

contract StealthPayTest is Test {
    MockAnnouncer ann; StealthPay pay; Tok tok; address payer = address(0xA11CE);
    bytes key = hex"02" hex"1111111111111111111111111111111111111111111111111111111111111111";
    function setUp() public {
        ann = new MockAnnouncer(); tok = new Tok(); pay = new StealthPay(address(ann), address(tok));
        tok.mint(payer, 1_000e6); vm.prank(payer); tok.approve(address(pay), type(uint256).max); vm.deal(payer, 10 ether);
    }
    function test_token_goes_straight_to_stealth_and_is_announced() public {
        address s = address(0xBEEF00);
        vm.prank(payer); pay.payToken(address(tok), 250e6, s, key, 0xAB);
        assertEq(tok.balanceOf(s), 250e6); assertEq(tok.balanceOf(address(pay)), 0);
        assertEq(ann.n(), 1); assertEq(ann.lastScheme(), 1); assertEq(ann.lastStealth(), s); assertEq(ann.lastCaller(), address(pay));
        assertEq(ann.lastKey(), key);
        assertEq(ann.lastMeta(), abi.encodePacked(bytes1(0xAB), bytes4(0xa9059cbb), address(tok), uint256(250e6)));
        assertEq(ann.lastMeta().length, 57, "ERC-5564 metadata layout: 1 + 4 + 20 + 32");
    }
    function test_eth_goes_straight_to_stealth_and_is_announced() public {
        address s = address(0xBEEF00);
        vm.prank(payer); pay.payETH{value: 1 ether}(s, key, 0x01);
        assertEq(s.balance, 1 ether); assertEq(address(pay).balance, 0);
        assertEq(ann.lastMeta(), abi.encodePacked(bytes1(0x01), bytes4(0xeeeeeeee), pay.ETH(), uint256(1 ether)));
    }
    function test_same_stealth_address_cannot_be_paid_twice_here() public {
        address s = address(0xBEEF00);
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
        vm.expectRevert(StealthPay.BadKey.selector); pay.payToken(address(tok), 1e6, address(0xBEEF00), hex"04" hex"11", 0x00);
        vm.expectRevert(StealthPay.BadKey.selector); pay.payToken(address(tok), 1e6, address(0xBEEF00), hex"02", 0x00);
        vm.stopPrank();
    }
    function test_zero_amount_reverts() public {
        vm.startPrank(payer);
        vm.expectRevert(StealthPay.ZeroAmount.selector); pay.payToken(address(tok), 0, address(0xBEEF00), key, 0x00);
        vm.expectRevert(StealthPay.ZeroAmount.selector); pay.payETH{value: 0}(address(0xBEEF00), key, 0x00);
        vm.stopPrank();
    }
    function test_failed_transfer_reverts_and_announces_nothing() public {
        address poor = address(0xB0B); vm.prank(poor); tok.approve(address(pay), 1e6);
        vm.prank(poor); vm.expectRevert(); pay.payToken(address(tok), 1e6, address(0xBEEF00), key, 0x00);
        assertEq(ann.n(), 0);
    }
    function test_eth_receiver_that_reenters_is_refused() public {
        Reenter r = new Reenter(pay);
        // a contract receiver is already refused as not fresh -- the lock is a second line
        vm.prank(payer); vm.expectRevert(abi.encodeWithSelector(StealthPay.NotFresh.selector, address(r)));
        pay.payETH{value: 1 ether}(address(r), key, 0x00);
    }

    // ---- additional checks (internal audit 26.10)
    function test_phantom_token_without_code_is_refused() public {
        address eth = pay.ETH();
        vm.prank(payer); vm.expectRevert(abi.encodeWithSelector(StealthPay.UnsupportedToken.selector, eth));
        pay.payToken(eth, 1e6, address(0xBEEF00), key, 0x00);
        vm.prank(payer); vm.expectRevert(abi.encodeWithSelector(StealthPay.UnsupportedToken.selector, address(0xC0FFEE)));
        pay.payToken(address(0xC0FFEE), 1e6, address(0xBEEF00), key, 0x00);
        assertEq(ann.n(), 0, "no announcement for money that did not move");
    }
    function testFuzz_token_amount_and_tag(uint96 amount, bytes1 tag, uint160 who) public {
        vm.assume(amount > 0 && who > 0xFFFF);
        address s = address(who); vm.assume(s != payer && s.code.length == 0 && !pay.used(s));
        tok.mint(payer, amount);
        uint256 before = tok.balanceOf(payer);
        vm.prank(payer); pay.payToken(address(tok), amount, s, key, tag);
        assertEq(tok.balanceOf(s), amount); assertEq(tok.balanceOf(payer), before - amount); assertEq(tok.balanceOf(address(pay)), 0);
        assertEq(ann.lastMeta(), abi.encodePacked(tag, bytes4(0xa9059cbb), address(tok), uint256(amount)));
        assertTrue(pay.used(s));
    }
    function testFuzz_eth_amount(uint96 wei_, uint160 who) public {
        vm.assume(wei_ > 0 && who > 0xFFFF);
        address s = address(who); vm.assume(s.balance == 0 && s.code.length == 0 && !pay.used(s));
        vm.deal(payer, uint256(wei_));
        vm.prank(payer); pay.payETH{value: wei_}(s, key, 0x11);
        assertEq(s.balance, wei_); assertEq(address(pay).balance, 0);
    }
    function test_token_returning_false_reverts() public {
        FalseTok f = new FalseTok(); StealthPay pay = new StealthPay(address(ann), address(f));
        vm.prank(payer); vm.expectRevert(StealthPay.TransferFailed.selector);
        pay.payToken(address(f), 1, address(0xBEEF00), key, 0x00);
        assertEq(ann.n(), 0);
    }
    function test_token_without_return_value_is_accepted() public {
        NoRetTok f = new NoRetTok(); StealthPay pay = new StealthPay(address(ann), address(f)); f.mint(payer, 5); vm.prank(payer); f.approve(address(pay), 5);
        vm.prank(payer); pay.payToken(address(f), 5, address(0xBEEF00), key, 0x00);
        assertEq(f.balanceOf(address(0xBEEF00)), 5); assertEq(ann.n(), 1);
    }
    function test_reentrant_token_cannot_reenter_pay() public {
        ReenterTok r = new ReenterTok(); StealthPay pay = new StealthPay(address(ann), address(r)); r.setPay(pay); r.mint(payer, 10); vm.prank(payer); r.approve(address(pay), 10);
        vm.prank(payer); vm.expectRevert(StealthPay.TransferFailed.selector);   // inner call reverts Reentrancy -> transferFrom fails
        pay.payToken(address(r), 10, address(0xBEEF00), key, 0x00);
    }
    function test_griefing_front_run_only_costs_a_retry() public {
        address s = address(0xBEEF00);
        address griefer = address(0xBAD); tok.mint(griefer, 1); vm.prank(griefer); tok.approve(address(pay), 1);
        vm.prank(griefer); pay.payToken(address(tok), 1, s, key, 0x00);           // 1 unit lands on X first
        vm.prank(payer); vm.expectRevert(abi.encodeWithSelector(StealthPay.NotFresh.selector, s));
        pay.payToken(address(tok), 100e6, s, key, 0x00);                            // real payment is refused, nothing lost
        assertEq(tok.balanceOf(payer), 1_000e6);
    }

    // ---- external audit 1076 fixes: one token per deployment
    function test_constructor_args() public {
        assertEq(pay.TOKEN(), address(tok)); assertEq(address(pay.ANNOUNCER()), address(ann));
        vm.expectRevert(StealthPay.NoAnnouncer.selector); new StealthPay(address(0xA11CE), address(tok));
        vm.expectRevert(StealthPay.NoAnnouncer.selector); new StealthPay(address(0), address(tok));
        vm.expectRevert(abi.encodeWithSelector(StealthPay.NotAToken.selector, address(0xA11CE))); new StealthPay(address(ann), address(0xA11CE));
        vm.expectRevert(abi.encodeWithSelector(StealthPay.NotAToken.selector, address(0))); new StealthPay(address(ann), address(0));
    }
    function test_fake_token_is_refused_by_payToken() public {
        MintlessTok fake = new MintlessTok();   // returns true, moves nothing, has code
        vm.prank(payer); vm.expectRevert(abi.encodeWithSelector(StealthPay.UnsupportedToken.selector, address(fake)));
        pay.payToken(address(fake), 1_000_000e6, address(0xBEEF00), key, 0x00);
        assertEq(ann.n(), 0); assertFalse(pay.used(address(0xBEEF00)));
    }
    function test_fee_on_transfer_delta_mismatch_is_refused() public {
        SkimTok f = new SkimTok(); StealthPay p2 = new StealthPay(address(ann), address(f));
        f.mint(payer, 100); vm.prank(payer); f.approve(address(p2), 100);
        vm.prank(payer); vm.expectRevert(StealthPay.AmountMismatch.selector);
        p2.payToken(address(f), 100, address(0xBEEF00), key, 0x00);
        assertEq(ann.n(), 0);
    }
    function test_low_addresses_are_refused() public {
        address[4] memory low = [address(1), address(9), address(0xBEEF), address(0xFFFF)];
        for (uint256 i; i < low.length; i++) {
            vm.prank(payer); vm.expectRevert(abi.encodeWithSelector(StealthPay.NotFresh.selector, low[i]));
            pay.payToken(address(tok), 1e6, low[i], key, 0x00);
            vm.prank(payer); vm.expectRevert(abi.encodeWithSelector(StealthPay.NotFresh.selector, low[i]));
            pay.payETH{value: 1}(low[i], key, 0x00);
        }
        vm.prank(payer); pay.payToken(address(tok), 1e6, address(0x10000), key, 0x00);   // boundary is allowed
        assertEq(ann.n(), 1);
    }
}
contract MintlessTok {
    function transferFrom(address, address, uint256) external pure returns (bool) { return true; }
    function transfer(address, uint256) external pure returns (bool) { return true; }
    function balanceOf(address) external pure returns (uint256) { return 0; }
}
contract SkimTok {
    mapping(address => uint256) public balanceOf; mapping(address => mapping(address => uint256)) public allowance;
    function mint(address t, uint256 a) external { balanceOf[t] += a; }
    function approve(address s, uint256 a) external returns (bool) { allowance[msg.sender][s] = a; return true; }
    function transferFrom(address f, address t, uint256 a) external returns (bool) { allowance[f][msg.sender] -= a; balanceOf[f] -= a; balanceOf[t] += a - 1; return true; }
}

contract FalseTok { function balanceOf(address) external pure returns (uint256) { return 0; } function transferFrom(address, address, uint256) external pure returns (bool) { return false; } }
contract NoRetTok {
    mapping(address => uint256) public balanceOf; mapping(address => mapping(address => uint256)) public allowance;
    function mint(address t, uint256 a) external { balanceOf[t] += a; }
    function approve(address s, uint256 a) external { allowance[msg.sender][s] = a; }
    function transferFrom(address f, address t, uint256 a) external { require(allowance[f][msg.sender] >= a && balanceOf[f] >= a); allowance[f][msg.sender] -= a; balanceOf[f] -= a; balanceOf[t] += a; }
}
contract ReenterTok {
    StealthPay p; mapping(address => uint256) public balanceOf; mapping(address => mapping(address => uint256)) public allowance;
    function setPay(StealthPay _p) external { p = _p; }
    function mint(address t, uint256 a) external { balanceOf[t] += a; }
    function approve(address s, uint256 a) external returns (bool) { allowance[msg.sender][s] = a; return true; }
    function transferFrom(address, address, uint256) external returns (bool) {
        p.payToken(address(this), 1, address(0xD00D00), hex"02" hex"1111111111111111111111111111111111111111111111111111111111111111", 0x00);
        return true;
    }
}
