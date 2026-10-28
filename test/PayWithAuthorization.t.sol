// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;
import "forge-std/Test.sol";
import {StealthPay} from "../src/StealthPay.sol";
import {MockAnnouncer} from "./StealthPay.t.sol";

/// Minimal EIP-3009 token: real EIP-712 signature check, receive requires msg.sender == to, nonces single-use.
contract Tok3009 {
    mapping(address => uint256) public balanceOf; mapping(bytes32 => bool) public usedNonce;
    bytes32 public immutable DOMAIN_SEPARATOR;
    bytes32 public constant RECEIVE_TYPEHASH = keccak256("ReceiveWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)");
    uint256 public skim; // fee-on-transfer simulation for the mismatch test
    constructor() { DOMAIN_SEPARATOR = keccak256(abi.encode(keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"), keccak256("Global Dollar"), keccak256("1"), block.chainid, address(this))); }
    function mint(address t, uint256 a) external { balanceOf[t] += a; }
    function setSkim(uint256 s) external { skim = s; }
    // adversarial knobs: a blocklisted address, and a callback fired during receive/transfer
    mapping(address => bool) public blocked; address public hookTo; bytes public hookData; bool public hookOnTransfer; bool public hookOk;
    function setBlocked(address a, bool b) external { blocked[a] = b; }
    function setHook(address to, bytes calldata d, bool onTransfer) external { hookTo = to; hookData = d; hookOnTransfer = onTransfer; }
    function _hook(bool isTransfer) internal { if (hookTo != address(0) && hookOnTransfer == isTransfer) { (bool ok,) = hookTo.call(hookData); hookOk = ok; } }
    function transfer(address t, uint256 a) external returns (bool) { require(!blocked[t], "blocked"); _hook(true); require(balanceOf[msg.sender] >= a, "balance"); balanceOf[msg.sender] -= a; balanceOf[t] += a; return true; }
    function receiveWithAuthorization(address from, address to, uint256 value, uint256 validAfter, uint256 validBefore, bytes32 nonce, uint8 v, bytes32 r, bytes32 s) external {
        require(msg.sender == to, "caller must be the payee"); _hook(false);
        require(block.timestamp > validAfter && block.timestamp < validBefore, "time");
        require(!usedNonce[nonce], "nonce used");
        bytes32 d = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, keccak256(abi.encode(RECEIVE_TYPEHASH, from, to, value, validAfter, validBefore, nonce))));
        require(ecrecover(d, v, r, s) == from && from != address(0), "bad signature");
        usedNonce[nonce] = true;
        require(balanceOf[from] >= value, "balance"); balanceOf[from] -= value; balanceOf[to] += value - skim;
    }
}

contract PayWithAuthorizationTest is Test {
    MockAnnouncer ann; StealthPay pay; Tok3009 tok;
    uint256 pk = 0xA11CE; address payer; address relayer = address(0x7E1A);
    bytes key = hex"03" hex"2222222222222222222222222222222222222222222222222222222222222222";

    function setUp() public {
        vm.warp(1_800_000_000);
        ann = new MockAnnouncer(); tok = new Tok3009(); pay = new StealthPay(address(ann), address(tok));
        payer = vm.addr(pk); tok.mint(payer, 1_000e6);
    }

    function _digest(address from, uint256 amount, bytes32 nonce) internal view returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", tok.DOMAIN_SEPARATOR(), keccak256(abi.encode(tok.RECEIVE_TYPEHASH(), from, address(pay), amount, uint256(0), uint256(2_000_000_000), nonce))));
    }

    function _sign(uint256 signer, uint256 amount, address stealth, bytes memory eph, bytes1 tag, uint256 fee, address feeTo)
        internal view returns (StealthPay.Authorization memory a)
    {
        bytes32 nonce = pay.paymentNonce(address(tok), stealth, eph, tag, fee, feeTo);
        a.from = vm.addr(signer); a.validAfter = 0; a.validBefore = 2_000_000_000;
        (a.v, a.r, a.s) = vm.sign(signer, _digest(a.from, amount, nonce));
    }

    function test_one_signature_pays_stealth_and_relayer_and_announces_net() public {
        address s = address(0xBEEF00);
        StealthPay.Authorization memory a = _sign(pk, 100e6, s, key, 0x2a, 0.05e6, relayer);
        vm.prank(relayer); pay.payWithAuthorization(address(tok), 100e6, s, key, 0x2a, 0.05e6, relayer, a);
        assertEq(tok.balanceOf(s), 99.95e6); assertEq(tok.balanceOf(relayer), 0.05e6); assertEq(tok.balanceOf(address(pay)), 0);
        assertEq(tok.balanceOf(payer), 900e6);
        assertEq(ann.lastMeta(), abi.encodePacked(bytes1(0x2a), bytes4(0xa9059cbb), address(tok), uint256(99.95e6)), "announces what arrives");
        assertEq(ann.lastStealth(), s); assertEq(ann.lastKey(), key); assertTrue(pay.used(s));
    }

    function test_anyone_may_submit_and_the_outcome_is_identical() public {
        address s = address(0xBEEF00);
        StealthPay.Authorization memory a = _sign(pk, 10e6, s, key, 0x01, 0.01e6, relayer);
        vm.prank(address(0xBAD)); pay.payWithAuthorization(address(tok), 10e6, s, key, 0x01, 0.01e6, relayer, a);
        assertEq(tok.balanceOf(relayer), 0.01e6, "fee goes to the signed recipient, not the submitter");
        assertEq(tok.balanceOf(address(0xBAD)), 0);
    }

    function test_signature_cannot_be_redirected() public {
        address s = address(0xBEEF00);
        StealthPay.Authorization memory a = _sign(pk, 10e6, s, key, 0x01, 0, address(0));
        vm.expectRevert(bytes("bad signature")); pay.payWithAuthorization(address(tok), 10e6, address(0xC0FFEE), key, 0x01, 0, address(0), a);
        bytes memory otherKey = hex"02" hex"3333333333333333333333333333333333333333333333333333333333333333";
        vm.expectRevert(bytes("bad signature")); pay.payWithAuthorization(address(tok), 10e6, s, otherKey, 0x01, 0, address(0), a);
        vm.expectRevert(bytes("bad signature")); pay.payWithAuthorization(address(tok), 10e6, s, key, 0x02, 0, address(0), a);
        vm.expectRevert(bytes("bad signature")); pay.payWithAuthorization(address(tok), 10e6, s, key, 0x01, 1e6, address(0xBAD), a);
        vm.expectRevert(bytes("bad signature")); pay.payWithAuthorization(address(tok), 11e6, s, key, 0x01, 0, address(0), a);
        assertEq(tok.balanceOf(payer), 1_000e6, "nothing moved");
        pay.payWithAuthorization(address(tok), 10e6, s, key, 0x01, 0, address(0), a);
        assertEq(tok.balanceOf(s), 10e6, "the honest call still works");
    }

    function test_signature_for_another_deployment_is_useless() public {
        StealthPay other = new StealthPay(address(ann), address(tok));
        address s = address(0xBEEF00);
        StealthPay.Authorization memory a = _sign(pk, 10e6, s, key, 0x01, 0, address(0));
        vm.expectRevert(bytes("bad signature")); other.payWithAuthorization(address(tok), 10e6, s, key, 0x01, 0, address(0), a);
    }

    function test_replay_and_double_pay_refused() public {
        address s = address(0xBEEF00);
        StealthPay.Authorization memory a = _sign(pk, 10e6, s, key, 0x01, 0, address(0));
        pay.payWithAuthorization(address(tok), 10e6, s, key, 0x01, 0, address(0), a);
        vm.expectRevert(abi.encodeWithSelector(StealthPay.NotFresh.selector, s)); pay.payWithAuthorization(address(tok), 10e6, s, key, 0x01, 0, address(0), a);
    }

    function test_fee_rules() public {
        address s = address(0xBEEF00);
        StealthPay.Authorization memory a = _sign(pk, 10e6, s, key, 0x01, 10e6, relayer);
        vm.expectRevert(StealthPay.BadFee.selector); pay.payWithAuthorization(address(tok), 10e6, s, key, 0x01, 10e6, relayer, a);
        vm.expectRevert(StealthPay.BadFee.selector); pay.payWithAuthorization(address(tok), 10e6, s, key, 0x01, 1, address(0), a);
        vm.expectRevert(StealthPay.BadFee.selector); pay.payWithAuthorization(address(tok), 10e6, s, key, 0x01, 1, address(pay), a);
        vm.expectRevert(StealthPay.ZeroAmount.selector); pay.payWithAuthorization(address(tok), 0, s, key, 0x01, 0, address(0), a);
    }

    function test_fee_on_transfer_token_refused() public {
        tok.setSkim(1);
        address s = address(0xBEEF00);
        StealthPay.Authorization memory a = _sign(pk, 10e6, s, key, 0x01, 0, address(0));
        vm.expectRevert(StealthPay.AmountMismatch.selector); pay.payWithAuthorization(address(tok), 10e6, s, key, 0x01, 0, address(0), a);
    }

    function test_freshness_and_key_rules_apply() public {
        StealthPay.Authorization memory a = _sign(pk, 10e6, address(tok), key, 0x01, 0, address(0));
        vm.expectRevert(abi.encodeWithSelector(StealthPay.NotFresh.selector, address(tok))); pay.payWithAuthorization(address(tok), 10e6, address(tok), key, 0x01, 0, address(0), a);
        vm.expectRevert(StealthPay.BadKey.selector); pay.payWithAuthorization(address(tok), 10e6, address(0xBEEF00), hex"04", 0x01, 0, address(0), a);
        vm.expectRevert(abi.encodeWithSelector(StealthPay.UnsupportedToken.selector, address(0x1234))); pay.payWithAuthorization(address(0x1234), 10e6, address(0xBEEF00), key, 0x01, 0, address(0), a);
    }

    function testFuzz_amount_fee_tag(uint64 amount, uint64 fee, bytes1 tag, uint160 sraw) public {
        amount = uint64(bound(amount, 1, 1_000e6)); fee = uint64(bound(fee, 0, amount - 1));
        address s = address(uint160(bound(sraw, 0x10000, type(uint160).max)));
        vm.assume(s != address(pay) && s != address(tok) && s != address(ann) && s != relayer && s != payer && s.code.length == 0);
        StealthPay.Authorization memory a = _sign(pk, amount, s, key, tag, fee, relayer);
        pay.payWithAuthorization(address(tok), amount, s, key, tag, fee, relayer, a);
        assertEq(tok.balanceOf(s), amount - fee); assertEq(tok.balanceOf(relayer), fee); assertEq(tok.balanceOf(address(pay)), 0);
        assertEq(ann.lastMeta(), abi.encodePacked(tag, bytes4(0xa9059cbb), address(tok), uint256(amount - fee)));
    }

    // ---- adversarial ----
    function _hookCall(bytes memory data, bool onTransfer) internal { tok.setHook(address(pay), data, onTransfer); }

    function test_reentry_during_receive_is_refused() public {
        address s = address(0xBEEF00); address s2 = address(0xBEE2);
        StealthPay.Authorization memory a = _sign(pk, 10e6, s, key, 0x01, 0, address(0));
        _hookCall(abi.encodeCall(StealthPay.payToken, (address(tok), 1, s2, key, bytes1(0x01))), false);
        pay.payWithAuthorization(address(tok), 10e6, s, key, 0x01, 0, address(0), a);
        assertFalse(tok.hookOk(), "reentrant call failed");
        assertFalse(pay.used(s2)); assertEq(tok.balanceOf(s), 10e6);
    }

    function test_reentry_during_payout_is_refused() public {
        address s = address(0xBEEF00); address s2 = address(0xBEE2);
        StealthPay.Authorization memory a = _sign(pk, 10e6, s, key, 0x01, 1e6, relayer);
        StealthPay.Authorization memory a2 = _sign(pk, 5e6, s2, key, 0x01, 0, address(0));
        _hookCall(abi.encodeCall(StealthPay.payWithAuthorization, (address(tok), 5e6, s2, key, bytes1(0x01), 0, address(0), a2)), true);
        pay.payWithAuthorization(address(tok), 10e6, s, key, 0x01, 1e6, relayer, a);
        assertFalse(tok.hookOk()); assertFalse(pay.used(s2)); assertEq(tok.balanceOf(address(pay)), 0);
    }

    function test_blocklisted_fee_recipient_or_stealth_reverts_atomically() public {
        address s = address(0xBEEF00);
        StealthPay.Authorization memory a = _sign(pk, 10e6, s, key, 0x01, 1e6, relayer);
        tok.setBlocked(relayer, true);
        vm.expectRevert(StealthPay.TransferFailed.selector); pay.payWithAuthorization(address(tok), 10e6, s, key, 0x01, 1e6, relayer, a);
        assertEq(tok.balanceOf(payer), 1_000e6); assertFalse(pay.used(s)); assertEq(tok.balanceOf(address(pay)), 0);
        tok.setBlocked(relayer, false); tok.setBlocked(s, true);
        vm.expectRevert(StealthPay.TransferFailed.selector); pay.payWithAuthorization(address(tok), 10e6, s, key, 0x01, 1e6, relayer, a);
        tok.setBlocked(s, false);
        pay.payWithAuthorization(address(tok), 10e6, s, key, 0x01, 1e6, relayer, a); // same signature still good: nonce was not burned
        assertEq(tok.balanceOf(s), 9e6);
    }

    function test_stray_tokens_do_not_break_or_leak() public {
        tok.mint(address(pay), 777);
        address s = address(0xBEEF00);
        StealthPay.Authorization memory a = _sign(pk, 10e6, s, key, 0x01, 1e6, relayer);
        pay.payWithAuthorization(address(tok), 10e6, s, key, 0x01, 1e6, relayer, a);
        assertEq(tok.balanceOf(address(pay)), 777, "stray untouched, nothing extra paid out");
        assertEq(tok.balanceOf(s), 9e6); assertEq(tok.balanceOf(relayer), 1e6);
    }

    function test_payToken_and_authorization_paths_share_freshness() public {
        address s = address(0xBEEF00);
        StealthPay.Authorization memory a = _sign(pk, 10e6, s, key, 0x01, 0, address(0));
        pay.payWithAuthorization(address(tok), 10e6, s, key, 0x01, 0, address(0), a);
        vm.expectRevert(abi.encodeWithSelector(StealthPay.NotFresh.selector, s));
        pay.payToken(address(tok), 1, s, key, 0x01);
    }

    function test_expired_or_early_authorization_reverts() public {
        address s = address(0xBEEF00);
        StealthPay.Authorization memory a = _sign(pk, 10e6, s, key, 0x01, 0, address(0));
        vm.warp(2_000_000_001);
        vm.expectRevert(bytes("time")); pay.payWithAuthorization(address(tok), 10e6, s, key, 0x01, 0, address(0), a);
        assertFalse(pay.used(s));
    }

    function test_fake_token_is_refused_by_payWithAuthorization() public {
        FakeAuthTok fake = new FakeAuthTok(); address s = address(0xBEEF00);
        StealthPay.Authorization memory a = _sign(pk, 10e6, s, key, 0x01, 0, address(0));
        vm.expectRevert(abi.encodeWithSelector(StealthPay.UnsupportedToken.selector, address(fake)));
        pay.payWithAuthorization(address(fake), 10e6, s, key, 0x01, 0, address(0), a);
        assertEq(ann.n(), 0);
    }
}
contract FakeAuthTok {
    function receiveWithAuthorization(address, address, uint256, uint256, uint256, bytes32, uint8, bytes32, bytes32) external {}
    function balanceOf(address) external pure returns (uint256) { return 0; }
    function transfer(address, uint256) external pure returns (bool) { return true; }
}
