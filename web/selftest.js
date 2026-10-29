import { deriveForPayment, checkAnnouncement, metaAddress, keysFromSignature, signKeyRequestWith, addressFromPriv, unhex, hex, secpUtils, decodeMetadata, KEY_DOMAIN, keyRequestTypedData } from "./stealth-crypto.js";
import { paymentNonce } from "./pay-auth.js";
import { CHAINS, pickChain, chainOfMeta } from "./chains.js";
import { signSession, encodeNonce, base58, encodeSecpSignature, randomSplit, buildQuoteRequest, personalHash, SESSION_SIGNIN } from "./private-withdraw.js";
const out = document.getElementById("out"); const lines = [];
const say = s => { lines.push(s); out.textContent = lines.join("\n"); };
try {
  const vectors = await (await fetch("./erc5564_vectors.json")).json();
  let ok = 0, bad = 0; const check = (name, pass) => { pass ? ok++ : bad++; if (!pass) say("FAIL " + name); };
  for (const v of vectors) {
    const s = deriveForPayment(v.meta, unhex(v.eph_priv));
    const keys = { spendPriv: unhex(v.spend_priv), viewPriv: unhex(v.view_priv), spendPub: secpUtils.getPublicKey(unhex(v.spend_priv), true), viewPub: secpUtils.getPublicKey(unhex(v.view_priv), true) };
    const r = checkAnnouncement(keys, v.eph_pub, v.view_tag);
    check("meta-address", metaAddress(keys).split(":")[2].toLowerCase() === v.meta.toLowerCase());
    check("sender stealth", s.stealth.toLowerCase() === v.stealth.toLowerCase());
    check("sender ephPub", s.ephPub.toLowerCase() === v.eph_pub.toLowerCase());
    check("sender viewTag", s.viewTag.toLowerCase() === v.view_tag.toLowerCase());
    check("receiver finds it", !!r && r.stealth.toLowerCase() === v.stealth.toLowerCase());
    check("receiver private key", !!r && r.stealthPriv.toLowerCase() === v.stealth_priv.toLowerCase());
  }
  const v0 = vectors[0]; const keys0 = { spendPriv: unhex(v0.spend_priv), viewPriv: unhex(v0.view_priv), spendPub: secpUtils.getPublicKey(unhex(v0.spend_priv), true), viewPub: secpUtils.getPublicKey(unhex(v0.view_priv), true) };
  check("wrong view tag rejected", checkAnnouncement(keys0, v0.eph_pub, "0x" + ((parseInt(v0.view_tag, 16) + 1) & 255).toString(16).padStart(2, "0")) === null);
  check("off-curve eph tolerated", checkAnnouncement(keys0, "0x02" + "ff".repeat(32), null) === null);
  const md = decodeMetadata("0x20a9059cbb833589fcd6edb6e08f4c7c32d4f71b54bda02913" + (42000000).toString(16).padStart(64, "0"));
  check("metadata decode", md && md.viewTag === "0x20" && md.token.toLowerCase() === "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913" && md.amount === 42000000n);
  check("garbage metadata tolerated", decodeMetadata("0x") === null && decodeMetadata("0x20") !== null);
  // key derivation: a plain EOA signature over the typed request must be accepted and verified; wrong account refused; v=0/27 same keys
  const priv = unhex("0x" + "45".repeat(32)); const account = addressFromPriv(priv);
  const sig27 = signKeyRequestWith(priv, account);
  const k1 = keysFromSignature(sig27, account), k2 = keysFromSignature(sig27, account);
  check("keys deterministic", hex(k1.spendPriv) === hex(k2.spendPriv) && hex(k1.viewPriv) === hex(k2.viewPriv) && hex(k1.spendPriv) !== hex(k1.viewPriv));
  const v27 = parseInt(sig27.slice(-2), 16); const sig0 = sig27.slice(0, -2) + (v27 - 27).toString(16).padStart(2, "0");
  const k3 = keysFromSignature(sig0, account);
  check("v=0/1 and v=27/28 give the same keys", hex(k3.spendPriv) === hex(k1.spendPriv));
  let threw = false; try { keysFromSignature(sig27, "0x" + "11".repeat(20)); } catch { threw = true; } check("wrong account refused", threw);
  threw = false; try { keysFromSignature(sig27.slice(0, -2), account); } catch { threw = true; } check("64-byte signature refused", threw);
  threw = false; try { keysFromSignature(sig27 + "00".repeat(40), account); } catch { threw = true; } check("wrapped/long signature refused", threw);
  const other = unhex("0x" + "46".repeat(32)); const sigOther = signKeyRequestWith(other, account);
  threw = false; try { keysFromSignature(sigOther, account); } catch { threw = true; } check("signature by another key refused", threw);
  // chain-independent key domain: no chainId anywhere, so every chain gives the same keys and wallets accept the request
  const td = JSON.parse(keyRequestTypedData(account));
  check("key domain has no chainId", !("chainId" in KEY_DOMAIN) && !("chainId" in td.domain) && !td.types.EIP712Domain.some(f => f.name === "chainId"));
  check("chain configs", CHAINS.base.chainId === 8453 && CHAINS.base.chainHex === "0x2105" && CHAINS.rh.chainId === 4663 && CHAINS.rh.chainHex === "0x1237" && CHAINS.rh.token.symbol === "USDG" && /^0x[0-9a-fA-F]{40}$/.test(CHAINS.rh.stealthPay));
  check("chain select", pickChain("?chain=rh").key === "rh" && pickChain("").key === "rh" && pickChain("?chain=base").key === "base" && pickChain("?to=st:rh:0xab").key === "rh" && chainOfMeta("st:rh:0x1").key === "rh" && chainOfMeta("0x1") === null);
  check("meta prefix per chain", metaAddress(k1, "rh").startsWith("st:rh:0x") && metaAddress(k1).startsWith("st:base:0x"));
  // one-signature payment: nonce must equal the value computed by `cast abi-encode` + `cast keccak` (== StealthPay.paymentNonce)
  check("paymentNonce matches cast", paymentNonce({ chainId: 4663, stealthPay: "0x1111111111111111111111111111111111111111", token: "0x5fc5360D0400a0Fd4f2af552ADD042D716F1d168", stealth: "0x2222222222222222222222222222222222222222", eph: "0x03" + "33".repeat(32), viewTag: "0x2a", fee: 50000n, feeRecipient: "0x4444444444444444444444444444444444444444" }) === "0x59b5c6887352a734851ed214c94808287ce1973432bd9756ff0ce0c95b38879b");
  // private withdraw (web/private-withdraw.js): payload, nonce and signature equal what @defuse-protocol/intents-sdk 0.93.0 produced for the same inputs
  {
    const gk = "0x" + "45".repeat(32), ga = addressFromPriv(unhex(gk)), dl = Date.parse("2026-10-28T12:05:00.000Z");
    const sdkNonce = "Vij2xgAlKBKzADiaWPyv4hgBAgMEBQYHCAkKCwwNDg8=";
    check("session: nonce equals the SDK's VersionedNonceBuilder.encodeNonce", encodeNonce(unhex("0x252812b3"), dl, Uint8Array.from([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15])) === sdkNonce);
    const sdkPayload = "{\"signer_id\":\"0xe0da1edcea030875cd0f199d96eb70f6ab78faf2\",\"verifying_contract\":\"intents.near\",\"deadline\":\"2026-10-28T12:05:00.000Z\",\"nonce\":\"" + sdkNonce + "\",\"intents\":[]}";
    const ss = signSession({ priv: gk, address: ga, saltHex: "252812b3", now: dl - 300_000, nonce: sdkNonce });
    check("session: payload string equals the SDK's (key order, lowercase signer, +5 min, empty intents)", ss.payload === sdkPayload && ss.standard === "erc191");
    check("session: signature equals the SDK's (personal_sign by the key, secp256k1:base58, v 0/1)", ss.signature === "secp256k1:FHcEzaJ3KT2cF4Kd9DCK6jPFrztwW2GKcgAikCni2fyd4Afv3ZX6ZJW9UjUS5SiMEtykxXpDXNakf7UqGkLwgtrjr");
    const live = JSON.parse(signSession({ priv: gk, address: ga, saltHex: "252812b3", now: dl - 300_000 }).payload), nb = Uint8Array.from(atob(live.nonce), c => c.charCodeAt(0));
    check("session: fresh nonce is 32 bytes, magic+version+salt, start time in the first 8 random bytes", nb.length === 32 && nb[0] === 0x56 && nb[4] === 0 && hex(nb.slice(5, 9)) === "0x252812b3" && new DataView(nb.buffer).getBigInt64(17, true) === BigInt(dl - 300_000) * 1000000n);
    const sg = secpUtils.sign(personalHash(sdkPayload), unhex(gk), { lowS: true });
    const sigHex = "0x" + sg.r.toString(16).padStart(64, "0") + sg.s.toString(16).padStart(64, "0") + (27 + sg.recovery).toString(16);
    check("session: v 27/28 is mapped to 0/1", encodeSecpSignature(sigHex) === ss.signature);
    check("base58 vectors", base58(unhex("0x00000000")) === "1111" && base58(new TextEncoder().encode("hello world")) === "StV1DL6CwTryKyV");
    check("session sign-in is off in the app", SESSION_SIGNIN === false);
  }
  { const tot = 10_000_000n; let okS = true; for (let i = 0; i < 200; i++) { const a = randomSplit(tot, 3); okS = okS && a.length === 3 && a.reduce((x, y) => x + y, 0n) === tot && a.every(x => x >= 1_000_000n); }
    check("randomSplit: sums to total, parts >= 1 token", okS); check("randomSplit: small total is not split below the minimum", randomSplit(1_500_000n, 3).length === 1 && randomSplit(2_500_000n, 3).length === 2); }
  { const r = buildQuoteRequest({ from: CHAINS.rh, to: CHAINS.base, amount: 5_000_000n, recipient: "0x" + "22".repeat(20), refundTo: "0x" + "11".repeat(20), dry: true, now: 0 });
    check("quote request: assets, refund to stealth, ORIGIN_CHAIN/DESTINATION_CHAIN", r.originAsset === "nep141:hood-0x5fc5360d0400a0fd4f2af552add042d716f1d168.omft.near" && r.destinationAsset === "nep141:base-0x833589fcd6edb6e08f4c7c32d4f71b54bda02913.omft.near" && r.refundTo === "0x" + "11".repeat(20) && r.refundType === "ORIGIN_CHAIN" && r.depositType === "ORIGIN_CHAIN" && r.recipientType === "DESTINATION_CHAIN" && r.swapType === "EXACT_INPUT" && r.slippageTolerance === 100 && r.confidentiality === "public" && r.amount === "5000000");
    check("chains: privateWithdraw flag on base and rh", CHAINS.base.privateWithdraw === true && CHAINS.rh.privateWithdraw === true); }
  say((bad ? "RESULT FAIL " : "RESULT PASS ") + ok + " checks ok, " + bad + " failed, vectors " + vectors.length);
} catch (e) { say("RESULT ERROR " + (e && e.stack || e)); }
