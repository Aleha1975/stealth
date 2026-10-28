// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

/// @title StealthPay
/// @dev ONE TOKEN PER DEPLOYMENT: the ERC-20 this contract serves (e.g. USDC on Base, USDG on Robinhood Chain) is the
///      immutable TOKEN set in the constructor, plus the native coin through payETH. payToken and payWithAuthorization
///      keep the `token` argument (stable ABI for the web app and the relayer) but revert unless token == TOKEN, so a
///      fake token cannot make phantom announcements. payToken also checks that the stealth address's balance grew by
///      exactly `amount`, so the announced amount is what arrived (fee-on-transfer and lying tokens are refused);
///      payWithAuthorization checks the same on the contract's own balance. Allowed paths: payToken(TOKEN),
///      payWithAuthorization(TOKEN), payETH. Stealth addresses below 0x10000 (precompiles / system range) are refused.
///      Residuals that remain: (1) the griefing front-run described below; (2) a rebasing or blocklisting TOKEN can
///      still revert a payment (nothing is lost); (3) TOKEN is trusted to behave as the chosen real token (USDC/USDG)
///      -- the deployer must pass the right address, it cannot be changed afterwards.
/// @notice Pay an ERC-20 or ETH to a one-time (ERC-5564) stealth address and publish the announcement in the same
///         transaction, so a payer's wallet needs one call instead of two (or, with payWithAuthorization, one
///         signature and no gas) and the receiver can always find the payment.
///         No owner, no upgrade, no protocol fee, no balance kept: tokens go straight from the payer to the stealth address
///         (transferFrom), ETH is forwarded in the same call. The announcement follows the ERC-5564 metadata layout:
///         view tag (1 byte) | function selector (4) | token (20) | amount (32); for ETH the token is 0xEeee...EEeE.
///
///         What a fresh address is here: no code at it. A contract cannot be a stealth address (its key is not derived
///         from the receiver's keys), and the same stealth address must not be paid twice through this contract: the
///         second payment would link two payers and two amounts to one receiver on chain. `used` enforces that for
///         payments made here; payments made elsewhere are the receiver's own concern. Residual: a watcher who sees a
///         pending payToken(stealth = X) could pay X one unit first and make the real payment revert with NotFresh; the
///         payer loses nothing but gas and retries with a new one-time address. Base has no public mempool, so this
///         needs the sequencer's cooperation; accepted. Same on Robinhood Chain (Arbitrum Orbit, private sequencer).
interface IAnnouncer {
    function announce(uint256 schemeId, address stealthAddress, bytes memory ephemeralPubKey, bytes memory metadata) external;
}
interface IERC20 {
    function transferFrom(address from, address to, uint256 value) external returns (bool);
    function transfer(address to, uint256 value) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}
/// EIP-3009 (USDC, USDG): only `to` may submit a receive authorization, so nobody can take a signed one and send it elsewhere.
interface IERC3009 {
    function receiveWithAuthorization(address from, address to, uint256 value, uint256 validAfter, uint256 validBefore, bytes32 nonce, uint8 v, bytes32 r, bytes32 s) external;
}

contract StealthPay {
    uint256 public constant SCHEME_ID = 1;                       // ERC-5564 secp256k1 with view tags
    address public constant ETH = 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE;
    bytes4 private constant SEL_TRANSFER = 0xa9059cbb;
    bytes4 private constant SEL_ETH = 0xeeeeeeee;
    IAnnouncer public immutable ANNOUNCER;
    address public immutable TOKEN;                              // the one ERC-20 served by this deployment

    /// The payer's EIP-3009 signature fields; grouped to keep the call within the stack limit without via-IR.
    struct Authorization { address from; uint256 validAfter; uint256 validBefore; uint8 v; bytes32 r; bytes32 s; }

    mapping(address => bool) public used;
    uint256 private _lock;

    event Paid(address indexed stealthAddress, address indexed token, uint256 amount);

    error Reentrancy();
    error ZeroAmount();
    error NotFresh(address stealthAddress);
    error BadKey();
    error TransferFailed();
    error EthFailed();
    error NotAToken(address token);
    error UnsupportedToken(address token);
    error NoAnnouncer();
    error BadFee();
    error AmountMismatch();

    constructor(address announcer, address token) {
        if (announcer.code.length == 0) revert NoAnnouncer();
        if (token.code.length == 0) revert NotAToken(token);
        ANNOUNCER = IAnnouncer(announcer);
        TOKEN = token;
    }

    modifier lock() { if (_lock != 0) revert Reentrancy(); _lock = 1; _; _lock = 0; }

    /// @notice Pay `amount` of `token` from the caller to `stealthAddress` and announce it.
    /// @param ephemeralPubKey the payer's one-time public key, 33 bytes compressed, as ERC-5564 scheme 1 requires
    /// @param viewTag the first byte of the hashed shared secret: lets the receiver skip 255 of 256 announcements
    function payToken(address token, uint256 amount, address stealthAddress, bytes calldata ephemeralPubKey, bytes1 viewTag) external lock {
        if (amount == 0) revert ZeroAmount();
        // Only the deployment's own token: any other contract could "succeed" without moving funds and so publish
        // announcements of payments that never happened (phantom amounts in the receiver's list) for the price of gas.
        if (token != TOKEN) revert UnsupportedToken(token);
        _fresh(stealthAddress, ephemeralPubKey);
        _pull(token, stealthAddress, amount);
        ANNOUNCER.announce(SCHEME_ID, stealthAddress, ephemeralPubKey, abi.encodePacked(viewTag, SEL_TRANSFER, token, amount));
        emit Paid(stealthAddress, token, amount);
    }

    /// @notice Gasless payment with ONE payer signature: the payer signs an EIP-3009 ReceiveWithAuthorization to this
    ///         contract and anyone (our relayer) submits it. The authorization nonce is not random: it is
    ///         paymentNonce(...), a hash of the stealth address, ephemeral key, view tag, fee and fee recipient, so the
    ///         signature commits to where the money goes and who earns the fee. A different destination, key, tag or
    ///         fee gives a different nonce and the token rejects the signature. The money passes through this contract
    ///         inside the one transaction (receive -> transfer), nothing stays here.
    /// @param fee part of `amount` paid to `feeRecipient` for the gas (0 allowed); the stealth address gets amount - fee
    function payWithAuthorization(
        address token, uint256 amount, address stealthAddress, bytes calldata ephemeralPubKey, bytes1 viewTag,
        uint256 fee, address feeRecipient, Authorization calldata auth
    ) external lock {
        if (amount == 0) revert ZeroAmount();
        if (fee >= amount || (fee != 0 && (feeRecipient == address(0) || feeRecipient == address(this)))) revert BadFee();
        if (token != TOKEN) revert UnsupportedToken(token);
        _fresh(stealthAddress, ephemeralPubKey);
        _receive(token, amount, paymentNonce(token, stealthAddress, ephemeralPubKey, viewTag, fee, feeRecipient), auth);
        if (fee != 0) _send(token, feeRecipient, fee);
        _deliver(token, stealthAddress, ephemeralPubKey, viewTag, amount - fee);
    }

    /// @notice The EIP-3009 nonce a payer signs for payWithAuthorization. Bound to this chain and this contract too, so a
    ///         signature for one deployment or chain is useless on another.
    function paymentNonce(address token, address stealthAddress, bytes calldata ephemeralPubKey, bytes1 viewTag, uint256 fee, address feeRecipient)
        public view returns (bytes32)
    {
        return keccak256(abi.encode(keccak256("StealthPay.payWithAuthorization"), block.chainid, address(this), token, stealthAddress, keccak256(ephemeralPubKey), viewTag, fee, feeRecipient));
    }

    /// @notice Pay the attached ETH to `stealthAddress` and announce it.
    function payETH(address stealthAddress, bytes calldata ephemeralPubKey, bytes1 viewTag) external payable lock {
        if (msg.value == 0) revert ZeroAmount();
        _fresh(stealthAddress, ephemeralPubKey);
        (bool ok, ) = stealthAddress.call{value: msg.value}("");
        if (!ok) revert EthFailed();
        ANNOUNCER.announce(SCHEME_ID, stealthAddress, ephemeralPubKey, abi.encodePacked(viewTag, SEL_ETH, ETH, msg.value));
        emit Paid(stealthAddress, ETH, msg.value);
    }

    function _receive(address token, uint256 amount, bytes32 nonce, Authorization calldata a) private {
        uint256 before = IERC20(token).balanceOf(address(this));
        IERC3009(token).receiveWithAuthorization(a.from, address(this), amount, a.validAfter, a.validBefore, nonce, a.v, a.r, a.s);
        if (IERC20(token).balanceOf(address(this)) - before != amount) revert AmountMismatch();
    }

    function _deliver(address token, address stealthAddress, bytes calldata ephemeralPubKey, bytes1 viewTag, uint256 net) private {
        _send(token, stealthAddress, net);
        ANNOUNCER.announce(SCHEME_ID, stealthAddress, ephemeralPubKey, abi.encodePacked(viewTag, SEL_TRANSFER, token, net));
        emit Paid(stealthAddress, token, net);
    }

    function _pull(address token, address stealthAddress, uint256 amount) private {
        uint256 before = IERC20(token).balanceOf(stealthAddress);
        (bool ok, bytes memory r) = token.call(abi.encodeWithSelector(IERC20.transferFrom.selector, msg.sender, stealthAddress, amount));
        if (!ok || (r.length != 0 && !abi.decode(r, (bool)))) revert TransferFailed();
        // The announced amount must be what arrived (replaces the fee-on-transfer residual).
        if (IERC20(token).balanceOf(stealthAddress) - before != amount) revert AmountMismatch();
    }

    function _send(address token, address to, uint256 value) private {
        (bool ok, bytes memory r) = token.call(abi.encodeWithSelector(IERC20.transfer.selector, to, value));
        if (!ok || (r.length != 0 && !abi.decode(r, (bool)))) revert TransferFailed();
    }

    function _fresh(address stealthAddress, bytes calldata ephemeralPubKey) private {
        if (uint160(stealthAddress) < 0x10000 || stealthAddress == address(this) || stealthAddress.code.length != 0 || used[stealthAddress]) revert NotFresh(stealthAddress);
        if (ephemeralPubKey.length != 33 || (ephemeralPubKey[0] != 0x02 && ephemeralPubKey[0] != 0x03)) revert BadKey();
        used[stealthAddress] = true;
    }
}
