# Phrasings safe to type on camera

The agents read a closed grammar: two sentence shapes, nothing else (`agent/parse.mjs`). Anything
outside it gets a question back, never a guess. These four sentences are the ones the demo uses.
`agent/parse.test.mjs` pins each to the payee and amount in the table and fails if this list and
the test disagree, so an edit to the parser that breaks a sentence you plan to say live breaks a
test instead of the recording.

Always write the amount as `0.50` or `7.00` with the word `USDC` after it, and name the payee once.
`{admin}` stands for the admin account in `deployments/testnet.json`; type the real account there.

| Say | Parses to payee | Amount (base units) | What the chain does |
|---|---|---|---|
| `pay Acme 0.50 USDC` | Acme Studio (pay1) | 500000 | allowed while the period has room; refused code 6 once it has not |
| `pay Inference 0.50 USDC` | Inference API (pay2) | 500000 | allowed while the period has room |
| `send 0.10 USDC to {admin}` | the admin account, not a vendor | 100000 | refused, code 4: not on the allow-list |
| `pay Acme 7.00 USDC` | Acme Studio (pay1) | 7000000 | refused, code 5: over the per-transaction limit (1.00) |

The scripted rule is 1.00 per transaction and 2.00 per day (`scripts/demo-beats.json`), so the
order in `docs/demo-script.md` is what makes the code 6 refusal happen.

Do not say: `5 000`, `1/2`, `3-5`, `3 or 5`, fullwidth digits or a fullwidth period, `pay me`,
`get`, `refund`. Those parse to a wrong amount or the wrong direction, and the agent asks a
question instead of sending anything.
