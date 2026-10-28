#!/bin/bash
# Тест индексатора на форке RH: announce'ы, глубина подтверждений, реорг (evm_revert) и сверка. Нужны anvil, cast, python3.
set -e
D=$(cd "$(dirname "$0")" && pwd); T=$(mktemp -d); R=http://127.0.0.1:8646; A=0x55649E01B5Df198D18D95b5cc5051630cfD45564
SP=0x00000000000000000000000000000000DeadBeef   # "StealthPay" для теста: его и ставим в STEALTHPAY
anvil --fork-url https://rpc.mainnet.chain.robinhood.com --port 8646 --silent & AP=$!
trap 'kill $AP $IP 2>/dev/null; rm -rf $T' EXIT
for i in $(seq 60); do cast block-number --rpc-url $R >/dev/null 2>&1 && break; sleep 1; done; cast block-number --rpc-url $R >/dev/null || { echo 'anvil did not start'; exit 1; }
cast rpc anvil_setBalance $SP 0xde0b6b3a7640000 --rpc-url $R >/dev/null; cast rpc anvil_impersonateAccount $SP --rpc-url $R >/dev/null
EPH=0x02$(printf 'ab%.0s' $(seq 1 32)); TOK=5fc5360d0400a0fd4f2af552add042d716f1d168
ann() { cast send $A "announce(uint256,address,bytes,bytes)" 1 $1 $EPH 0x11a9059cbb${TOK}$(printf '%064x' $2) --from $SP --unlocked --rpc-url $R >/dev/null; }
S1=0x00000000000000000000000000000000000a0001; S2=0x00000000000000000000000000000000000a0002; S3=0x00000000000000000000000000000000000a0003; S4=0x00000000000000000000000000000000000a0004
ann $S1 5000000; ann $S2 10                      # S1: $5 (известный), S2: 10 микро (ниже минимума)
STEALTH_CHAIN=rh STEALTH_RPC=$R STEALTH_DB=$T/i.db STEALTH_PORT=3975 STEALTH_START_BLOCK=$(( $(cast block-number --rpc-url $R) - 100 )) STEALTH_CONFIRMATIONS=5 STEALTH_RECONCILE_EVERY=3 STEALTHPAY=$SP python3 -B "$D/stealth_indexer.py" > $T/idx.log 2>&1 & IP=$!
J() { curl -s "localhost:3975$1"; echo; }
AB=$(cast block-number --rpc-url $R)   # блок последнего announce (S1,S2 отправлены выше)
waitidx() { for i in $(seq 60); do h=$(curl -s "localhost:3975/head" | python3 -c "import sys,json; print(json.load(sys.stdin).get('head') or 0)" 2>/dev/null || echo 0); [ "${h:-0}" -ge "$1" ] && return 0; sleep 1; done; echo "indexer head did not reach $1"; return 1; }
for i in $(seq 60); do curl -s localhost:3975/head >/dev/null 2>&1 && break; sleep 0.5; done
echo "-- до подтверждений (5 блоков): строк пока нет"; J /head
cast rpc anvil_mine 6 --rpc-url $R >/dev/null; waitidx $AB; echo "-- после 6 блоков"; J /head; J "/announcements?limit=5" | head -c 400; echo
echo "-- /known S1 (5 USDG) и S2 (мелкая):"; J "/known?addr=$S1"; J "/known?addr=$S2"
SNAP=$(cast rpc evm_snapshot --rpc-url $R | tr -d '"'); ann $S3 7000000; cast rpc anvil_mine 6 --rpc-url $R >/dev/null; sleep 4
echo "-- S3 объявлен и виден (до реорга):"; J "/known?addr=$S3"; J /head
cast rpc evm_revert $SNAP --rpc-url $R >/dev/null; ann $S4 8000000; cast rpc anvil_mine 8 --rpc-url $R >/dev/null; sleep 9
echo "-- после реорга: S3 исчез, S4 появился:"; J "/known?addr=$S3"; J "/known?addr=$S4"; J /head; grep -E "reconcile|went back" $T/idx.log
echo "-- /balances 150 адресов (>100) -> 400, 3 адреса -> ок:"; curl -s -o /dev/null -w "%{http_code}\n" "localhost:3975/balances?addrs=$(python3 -c "print(','.join('0x%040x'%i for i in range(1,152)))")"; J "/balances?addrs=$S1,$SP"
