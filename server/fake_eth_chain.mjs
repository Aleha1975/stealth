/* A tiny fake EVM chain for the ETH-path tests (no network, no funds). It speaks the JSON-RPC methods web/eth-send.js uses, and it PARSES every raw transaction it is given with viem
   (sender recovered from the signature, nonce, price, gas, destination, value), so a test fails if the bytes the page signs are not what the chain would accept.
   Knobs: refuse (next send is answered with this RPC error), dropAnswer (the transaction is applied but the answer is lost: a network error), revertNext (mined with status 0: gas is paid, the value does not move),
   hideReceipt (a lagging node), bump(addr) (another transaction uses the next nonce). */
import { parseTransaction, recoverTransactionAddress, keccak256 } from "viem";
const hx = n => "0x" + BigInt(n).toString(16);
export function makeEthChain({ chainId = 4663, gasPrice = 1_000_000_000n, gasEst = 21000n, onApply = null } = {}) {
  const c = { chainId, bal: new Map(), nonce: new Map(), mined: new Map(), sends: [], calls: [], refuse: null, dropAnswer: 0, revertNext: false, hideReceipt: false, gasPrice, gasEst, gasUsed: 21000n, estFail: null };
  const key = a => String(a).toLowerCase(), balOf = a => c.bal.get(key(a)) ?? 0n, nonceOf = a => c.nonce.get(key(a)) ?? 0;
  c.set = (a, v) => c.bal.set(key(a), v); c.balOf = balOf; c.nonceOf = nonceOf;
  c.bump = a => c.nonce.set(key(a), nonceOf(a) + 1);
  const rpcErr = m => Object.assign(new Error(m), { rpc: true });
  c.rpc = async (method, params = []) => {
    c.calls.push(method);
    switch (method) {
      case "eth_estimateGas": if (c.estFail) throw rpcErr(c.estFail); return hx(c.gasEst);
      case "eth_gasPrice": return hx(c.gasPrice);
      case "eth_getBalance": return hx(balOf(params[0]));
      case "eth_getTransactionCount": return hx(nonceOf(params[0]));
      case "eth_blockNumber": return "0x10";
      case "eth_getTransactionReceipt": { const m = c.mined.get(String(params[0]).toLowerCase()); if (!m || c.hideReceipt) return null; return { transactionHash: params[0].toLowerCase(), status: m.ok ? "0x1" : "0x0", logs: [], from: m.from, to: m.to, blockNumber: "0x10" }; }
      case "eth_getTransactionByHash": { const m = c.mined.get(String(params[0]).toLowerCase()); return m ? { hash: params[0].toLowerCase(), from: m.from, nonce: hx(m.nonce), blockNumber: "0x10" } : null; }
      case "eth_sendRawTransaction": {
        const raw = params[0]; c.sends.push(raw);
        if (c.refuse) { const m = c.refuse; c.refuse = null; throw rpcErr(m); }
        const tx = parseTransaction(raw), from = key(await recoverTransactionAddress({ serializedTransaction: raw })), hash = keccak256(raw);
        if (c.mined.has(hash)) throw rpcErr("already known");
        if (tx.chainId !== c.chainId) throw rpcErr("invalid chain id for signer");
        if (tx.nonce < nonceOf(from)) throw rpcErr("nonce too low");
        if (tx.nonce > nonceOf(from)) throw rpcErr("nonce too high");
        const cost = tx.gasPrice * tx.gas + tx.value;
        if (balOf(from) < cost) throw rpcErr("insufficient funds for gas * price + value");
        const ok = !c.revertNext; c.revertNext = false;
        c.set(from, balOf(from) - tx.gasPrice * c.gasUsed - (ok ? tx.value : 0n)); if (ok) c.set(tx.to, balOf(tx.to) + tx.value); c.nonce.set(from, tx.nonce + 1);
        c.mined.set(hash, { from, to: key(tx.to), value: tx.value, nonce: tx.nonce, ok, gas: tx.gas, gasPrice: tx.gasPrice });
        if (ok && onApply) onApply({ from, to: key(tx.to), value: tx.value, hash });
        if (c.dropAnswer > 0) { c.dropAnswer--; throw new Error("network down"); }
        return hash;
      }
      default: throw rpcErr("method not supported by the fake chain: " + method);
    }
  };
  return c;
}
