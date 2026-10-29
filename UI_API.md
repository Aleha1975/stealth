# UI contract

The real app script fills and reads these elements by id. Change styling freely; keep the ids and element types.

## Shared
- `wbtn` (button): "Connect wallet" / short address; class `on` when connected.
- `.chain-name`, `.tok-sym` (spans): chain name and token symbol are written in.

## Tabs
- `.tabs button[data-pane=receive|payments|pay]` with `aria-selected`; panes `pane-receive`, `pane-payments`, `pane-pay` toggled with `hidden`.
- Deep links: `app.html?tab=pay|receive|payments`, `app.html?to=<meta-address>` opens Pay with the recipient filled in.

## Receive
- `btn-keys` (button) → asks the wallet for one signature.
- `recv-out` (shown after): `meta` (meta-address text), `paylink` (link text), `copy-link`, `copy-meta` (buttons).
- `recv-hint` (status line; classes `ok`, `warn`, `bad`).

## My payments
- `btn-scan`, `scan-note`, `pay-list` (rows: `.pay` > `.amt`, `.mono`, `small`, a "Withdraw" button).
- `hop-resume`: private-transfer progress cards (`.hop` + `done|warn|bad`, `.hop-t`, `.hop-amt`, `.hop-fill > i` width = %, `.hop-pct`, `.hop-bar > i` with `d`/`c`, `.hop-step`, `.hop-line`, `.hop-act` buttons "Continue transfer", "Return money", "Dismiss").
- `withdraw` form: `wd-from`, `wd-to`, `wd-amt`, `wd-priv-wrap`, `wd-private` (checkbox), `wd-priv-opts`, `wd-dest` (hidden select), `wd-mode` (fast / private), `wd-quote` (quote box: `.qt` with three cells), `btn-wd`, `btn-wd-cancel`.
- `pay-hint`: status line; during a private transfer it shows "● 42% · ≈ 18 min left · …" in green.

## Pay someone
- `to-meta` (recipient link), `amount` (you pay) and `amount-get` (receiver gets) are linked; `token` select; `pay-calc` (fee line); `btn-pay`; `send-hint`.

## Footer
- `sp-addr`: pay contract address.
