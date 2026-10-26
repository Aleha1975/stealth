// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/// @title StealthPay
/// @notice Pay an ERC-20 or ETH to a one-time (ERC-5564) stealth address and publish the announcement in the same
///         transaction, so a payer's wallet needs one call instead of two and the receiver can always find the payment.
///         No owner, no upgrade, no fee, no balance kept: tokens go straight from the payer to the stealth address
///         (transferFrom), ETH is forwarded in the same call. The announcement follows the ERC-5564 metadata layout:
///         view tag (1 byte) | function selector (4) | token (20) | amount (32); for ETH the token is 0xEeee...EEeE.
///
///         What a fresh address is here: no code at it. A contract cannot be a stealth address (its key is not derived
///         from the receiver's keys), and the same stealth address must not be paid twice through this contract: the
///         second payment would link two payers and two amounts to one receiver on chain. `used` enforces that for
///         payments made here; payments made elsewhere are the receiver's own concern. Residual: a watcher who sees a
///         pending payToken(stealth = X) could pay X one unit first and make the real payment revert with NotFresh; the
///         payer loses nothing but gas and retries with a new one-time address. Base has no public mempool, so this
///         needs the sequencer's cooperation; accepted.
interface IAnnouncer {
    function announce(uint256 schemeId, address stealthAddress, bytes memory ephemeralPubKey, bytes memory metadata) external;
}
interface IERC20 {
    function transferFrom(address from, address to, uint256 value) external returns (bool);
}

contract StealthPay {
    uint256 public constant SCHEME_ID = 1;                       // ERC-5564 secp256k1 with view tags
    address public constant ETH = 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE;
    bytes4 private constant SEL_TRANSFER = 0xa9059cbb;
    bytes4 private constant SEL_ETH = 0xeeeeeeee;
    IAnnouncer public immutable ANNOUNCER;

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

    constructor(address announcer) {
        if (announcer.code.length == 0) revert BadKey();
        ANNOUNCER = IAnnouncer(announcer);
    }

    modifier lock() { if (_lock != 0) revert Reentrancy(); _lock = 1; _; _lock = 0; }

    /// @notice Pay `amount` of `token` from the caller to `stealthAddress` and announce it.
    /// @param ephemeralPubKey the payer's one-time public key, 33 bytes compressed, as ERC-5564 scheme 1 requires
    /// @param viewTag the first byte of the hashed shared secret: lets the receiver skip 255 of 256 announcements
    function payToken(address token, uint256 amount, address stealthAddress, bytes calldata ephemeralPubKey, bytes1 viewTag) external lock {
        if (amount == 0) revert ZeroAmount();
        // A call to an address without code "succeeds" with empty return data: without this check anyone could publish
        // announcements of payments that never happened (phantom amounts in the receiver's list) for the price of gas.
        if (token.code.length == 0) revert NotAToken(token);
        _fresh(stealthAddress, ephemeralPubKey);
        (bool ok, bytes memory r) = token.call(abi.encodeWithSelector(IERC20.transferFrom.selector, msg.sender, stealthAddress, amount));
        if (!ok || (r.length != 0 && !abi.decode(r, (bool)))) revert TransferFailed();
        ANNOUNCER.announce(SCHEME_ID, stealthAddress, ephemeralPubKey, abi.encodePacked(viewTag, SEL_TRANSFER, token, amount));
        emit Paid(stealthAddress, token, amount);
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

    function _fresh(address stealthAddress, bytes calldata ephemeralPubKey) private {
        if (stealthAddress == address(0) || stealthAddress == address(this) || stealthAddress.code.length != 0 || used[stealthAddress]) revert NotFresh(stealthAddress);
        if (ephemeralPubKey.length != 33 || (ephemeralPubKey[0] != 0x02 && ephemeralPubKey[0] != 0x03)) revert BadKey();
        used[stealthAddress] = true;
    }
}
