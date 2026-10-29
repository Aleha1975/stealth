# Loophole — design branch

Private payments on Robinhood Chain: one link to receive stablecoins, a fresh address for every payment, gasless pay and withdraw.
This branch holds **only the design**: pages, styles, motion and copy. The app runs on mock data — no wallet, no network, no keys.

## Run

```
cd web && python3 -m http.server 8080
# open http://localhost:8080/          landing
#      http://localhost:8080/app.html  app (mock data)
```

No build step, no dependencies.

## Structure

| File | What |
|---|---|
| `web/index.html` | Landing: hero, problem, how it works, features, security, roadmap, final CTA |
| `web/app.html` | App: Receive / My payments / Pay someone |
| `web/loophole.css` | All styles and tokens (`:root`), shared by both pages |
| `web/funnel.js` | Hero wormhole animation (canvas 2D, no libraries) |
| `web/landing.js`, `web/nav.js` | Landing redirect for pay links, nav helpers |
| `web/app-mock.js` | Fake app logic so every state can be clicked through |
| `UI_API.md` | Element ids and states the real app code drives — keep them |

## How to work

1. Branch from `loophole`: `design/<topic>` (e.g. `design/hero-mobile`).
2. Open a pull request into `loophole`. The owner reviews and merges.
3. Keep every element `id` listed in `UI_API.md` (the real app finds elements by id). Classes, layout and copy are yours to change.
4. Keep the page CSP: no inline `<script>`, no external scripts or fonts (self-host them in `web/`).
5. Mobile first: check 390 px wide, no horizontal scroll.

## Off-limits

- Keys, seed phrases, `.env` files, API tokens — never commit any.
- Wallet, relayer, contract or indexer logic — not part of this branch; don't add network calls.
- Don't rename or remove the ids in `UI_API.md`.
