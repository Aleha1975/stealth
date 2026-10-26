#!/usr/bin/env python3
"""Эталон ERC-5564, схема 1 (secp256k1 + метка просмотра), на coincurve + keccak. Нужен, чтобы сверить
браузерную реализацию: печатает тест-векторы (JSON) и проверяет самосогласованность.

Схема (текст EIP-5564):
  получатель: мета-адрес = P_spend || P_view (по 33 байта, сжатые)
  плательщик: p_eph случайный; S = p_eph * P_view (сжатая точка, 33 байта); s_h = keccak256(S);
              view_tag = s_h[0]; P_stealth = P_spend + s_h*G; адрес = keccak256(uncompressed P_stealth[1:])[-20:]
              публикует P_eph (33 байта) и metadata = view_tag || ...
  получатель: S' = p_view * P_eph; s_h' = keccak256(S'); сверяет метку; p_stealth = (p_spend + s_h') mod n
"""
import json, os, sys
from coincurve import PrivateKey, PublicKey
from eth_hash.auto import keccak

N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def addr_of(pub: PublicKey) -> str:
    return "0x" + keccak(pub.format(compressed=False)[1:])[-20:].hex()


def shared(priv_bytes: bytes, pub: PublicKey) -> bytes:
    # S = priv * Pub, сжатая точка 33 байта; keccak256 от неё
    return keccak(pub.multiply(priv_bytes).format(compressed=True))


def sender(meta_hex: str, eph_priv: bytes):
    m = bytes.fromhex(meta_hex[2:] if meta_hex.startswith("0x") else meta_hex)
    assert len(m) == 66, "meta-address must be 66 bytes"
    P_spend, P_view = PublicKey(m[:33]), PublicKey(m[33:])
    s_h = shared(eph_priv, P_view)
    P_stealth = P_spend.combine([PublicKey.from_secret(s_h)])
    return {"stealth": addr_of(P_stealth), "eph_pub": "0x" + PrivateKey(eph_priv).public_key.format(compressed=True).hex(),
            "view_tag": "0x%02x" % s_h[0]}


def receiver(spend_priv: bytes, view_priv: bytes, eph_pub_hex: str, view_tag: str):
    P_eph = PublicKey(bytes.fromhex(eph_pub_hex[2:]))
    s_h = shared(view_priv, P_eph)
    if "0x%02x" % s_h[0] != view_tag:
        return None
    p = (int.from_bytes(spend_priv, "big") + int.from_bytes(s_h, "big")) % N
    priv = p.to_bytes(32, "big")
    return {"stealth_priv": "0x" + priv.hex(), "stealth": addr_of(PrivateKey(priv).public_key)}


def meta_address(spend_priv: bytes, view_priv: bytes) -> str:
    return "0x" + PrivateKey(spend_priv).public_key.format(compressed=True).hex() + PrivateKey(view_priv).public_key.format(compressed=True).hex()


if __name__ == "__main__":
    vectors = []
    for i in range(3):
        sp, vp, ep = os.urandom(32), os.urandom(32), os.urandom(32)
        meta = meta_address(sp, vp)
        s = sender(meta, ep)
        r = receiver(sp, vp, s["eph_pub"], s["view_tag"])
        assert r and r["stealth"] == s["stealth"], "sender/receiver disagree"
        vectors.append({"spend_priv": "0x" + sp.hex(), "view_priv": "0x" + vp.hex(), "eph_priv": "0x" + ep.hex(), "meta": meta,
                        "eph_pub": s["eph_pub"], "view_tag": s["view_tag"], "stealth": s["stealth"], "stealth_priv": r["stealth_priv"]})
    # фиксированный вектор для браузерного самотеста
    sp = bytes.fromhex("11" * 32); vp = bytes.fromhex("22" * 32); ep = bytes.fromhex("33" * 32)
    meta = meta_address(sp, vp); s = sender(meta, ep); r = receiver(sp, vp, s["eph_pub"], s["view_tag"])
    vectors.append({"spend_priv": "0x" + sp.hex(), "view_priv": "0x" + vp.hex(), "eph_priv": "0x" + ep.hex(), "meta": meta,
                    "eph_pub": s["eph_pub"], "view_tag": s["view_tag"], "stealth": s["stealth"], "stealth_priv": r["stealth_priv"], "fixed": True})
    print(json.dumps(vectors, indent=1))
