#!/usr/bin/env python3
"""Download the official OFAC SDN list and extract every EVM address (0x + 40 hex) into evm.json.
Source: https://sanctionslistservice.ofac.treas.gov/api/PublicationPreview/exports/SDN.XML  (same file as treasury.gov/ofac/downloads/sdn.xml)
EVM addresses appear as <id> entries of type "Digital Currency Address - ETH/USDT/USDC/ARB/BSC/..." (same 0x key on every EVM chain), and
occasionally inside remarks; both are collected. Output (sorted, lowercase): {"source","published","fetched","count","addresses":[...]}.
Usage: python3 update.py [--out evm.json] [--file local_sdn.xml]. Exit 1 on download/parse failure or if the list shrinks by >50% (never writes then)."""
import argparse, json, os, re, sys, urllib.request, datetime, tempfile
URL = "https://sanctionslistservice.ofac.treas.gov/api/PublicationPreview/exports/SDN.XML"
HERE = os.path.dirname(os.path.abspath(__file__))
ADDR = re.compile(r"(?<![0-9a-fA-F])0x[0-9a-fA-F]{40}(?![0-9a-fA-F])")
ID = re.compile(r"<id>(.*?)</id>", re.S)

def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--out", default=os.path.join(HERE, "evm.json")); ap.add_argument("--file")
    a = ap.parse_args()
    if a.file: raw = open(a.file, encoding="utf-8").read()
    else:
        req = urllib.request.Request(URL, headers={"User-Agent": "stealth-sanctions-update/1"})
        raw = urllib.request.urlopen(req, timeout=180).read().decode("utf-8")
    m = re.search(r"<Publish_Date>([^<]+)</Publish_Date>", raw); pub = m.group(1) if m else None
    if not pub or "<sdnList" not in raw: sys.exit("not an SDN document")
    found, typed = set(), set()
    for blk in ID.findall(raw):
        t = re.search(r"<idType>([^<]*)</idType>", blk); n = re.search(r"<idNumber>([^<]*)</idNumber>", blk)
        if t and n and t.group(1).startswith("Digital Currency Address"):
            for x in ADDR.findall(n.group(1)): typed.add(x.lower())
    for x in ADDR.findall(raw): found.add(x.lower())          # also remarks / aliases
    addrs = sorted(typed | found)
    if not addrs: sys.exit("no EVM addresses found: refusing to write an empty list")
    try: old = json.load(open(a.out)).get("count", 0)
    except Exception: old = 0
    if old and len(addrs) < old * 0.5: sys.exit(f"list shrank {old} -> {len(addrs)}; refusing to overwrite")
    doc = {"source": URL, "published": pub, "fetched": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "count": len(addrs), "addresses": addrs}
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(os.path.abspath(a.out))); os.write(fd, (json.dumps(doc, indent=1) + "\n").encode()); os.close(fd)
    os.chmod(tmp, 0o644); os.replace(tmp, a.out)               # atomic: the relayer watches this file
    print(f"wrote {a.out}: {len(addrs)} addresses (typed-id {len(typed)}, any-text {len(found)}), published {pub}")
main()
