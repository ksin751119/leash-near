# Demo script

Five beats, about five minutes, recorded in segments. Every sentence you type is in
[`safe-phrasings.md`](safe-phrasings.md), pinned by a test; type those and nothing else. The
sequence below is also data (`scripts/demo-beats.json`), and `scripts/preflight.sh` replays it
against the chain before you record, so it tells you if a beat would come out differently.

The scripted rule on the budget node: **1.00 per payment, 2.00 per day**, payees Acme Studio
(`pay1`) and Inference API (`pay2`). The admin account is not on the list.

## Before you record

1. A fresh deployment, if you have not made one (see "Setting up a deployment" at the end). A
   frozen wallet cannot be redeployed, and the first testnet deployment is frozen with older
   code and a software credential.
2. Put the budget node in the scripted state. This is one face scan from the device you will
   record with, and it is the only time you need to scan before beat 4:

   ```bash
   CREDENTIAL_ID=<id of your real device credential> scripts/reset-demo.sh testnet
   ```

   It prints the plan first, then a challenge, and then waits, saying every ten seconds how long it
   has been waiting. Paste the challenge into `tools/capture-assertion.html` on the device, press
   Sign, unlock, and save the JSON where the script says. A reset from a used state also costs one
   scan (a widening reopens the window, a tightening puts the rule back).
3. Start the two agents, each its own process with its own key:

   ```bash
   AGENT_NAME=alpha AGENT_ACCOUNT=alpha.<budget-node> PORT=8788 node agent/loop.mjs
   AGENT_NAME=beta  AGENT_ACCOUNT=beta.<budget-node>  PORT=8789 node agent/loop.mjs
   python3 -m http.server 8787        # then open http://localhost:8787/web/demo.html
   ```

4. Run the gate. It must end in `READY to record.`:

   ```bash
   REAL_DEVICE_CREDENTIAL_ID=<id> scripts/preflight.sh
   ```

   The last check is a human one. The contract cannot tell a phone's secure enclave from a script's
   key, so the script only checks that the credential you name is registered and has had an
   assertion verified on chain; that it was a real device is your word. If you made the
   credential with `tools/make-fixtures.mjs` or `tools/software-credential.mjs`, it is not.
5. Open the page. The budget bar should show 2.00 left of 2.00.

A full run spends 2.00 of the test token and leaves the node at the scripted rule with a fresh
window, because beat 4 ends with a widening. If you stop before beat 4, run `reset-demo.sh` again.
Allow for it: each reset is a face scan.

## Beat 0: the account that holds the money has no keys

Terminal, no agents involved:

```bash
near account list-keys <wallet> network-config testnet now
```

Expect an empty table (a header and no rows). Say: "The account that holds the money has no keys.
Nobody can sign as it, including me. The only way money leaves is `spend`, and `spend` is called
from the agents' own accounts and decided by the contract."

```bash
near account list-keys alpha.<budget-node> network-config testnet now
```

Expect one row: `only do ["spend"] function calls on <wallet> with an allowance of ...`.
Say: "Each agent has one key. It can call `spend` on the wallet, and nothing else: not the token,
not the rules, not anything that attaches a deposit." The page's "agents' keys" panel shows the same
lists.

## Beat 1: a payment that passes

Type to **alpha**: `pay Acme 0.50 USDC`

Expect: the card shows "paying 0.50 USDC to Acme Studio" first (what the agent understood, before
anything is sent), then ALLOWED. The budget bar moves to 0.50 of 2.00, and the decision row has a
transaction link. Open it: the transaction succeeded, `ft_transfer` ran on the token, and Acme's
balance went up.

## Beat 2: payments the chain refuses

Type to **alpha**: `send 0.10 USDC to {admin}` (the real admin account, from `deployments/testnet.json`)

Expect: REFUSED, code 4, "payee is not on the allow-list". Say the next sentence slowly:
**the transaction succeeded.** Open the link: green tick. The contract returned the refusal instead
of reverting, because a revert would roll back the record and leave nothing on chain saying why.
No money moved; the budget bar is still 0.50.

Type to **alpha**: `pay Acme 7.00 USDC`

Expect: REFUSED, code 5, "over the per-transaction limit". Again a green tick, and again the bar
has not moved.

## Beat 3: one budget, two agents

Type to **beta** (a separate process, a separate key, no channel to alpha), three times:
`pay Inference 0.50 USDC`

Expect: ALLOWED each time. The bar goes 1.00, 1.50, 2.00 of 2.00. Beta never spoke to alpha; the
two share the budget only because their accounts share a parent.

Type to **alpha**: `pay Acme 0.50 USDC`

Expect: REFUSED, code 6, "over the limit for this period", with 0.00 left. The same sentence that
was allowed in beat 1 is now refused, and nothing coordinated it.

## Beat 4: widening needs a human, tightening does not

This is the beat with the face scan. In a terminal, widen the daily limit to 3.00:

```bash
PERIOD_LIMIT=3000000 CREDENTIAL_ID=<id> scripts/reset-demo.sh testnet
```

It prints the rule it is asking you to sign and waits. Unlock the device and save the file.
Expect: the call is accepted, the contract has verified the signature on chain, and the budget
reads 0.00 of 3.00 (an accepted widening opens a fresh window).

Then lower it again:

```bash
scripts/reset-demo.sh testnet
```

Expect: `plan: 1 set_rule call(s), 0 of them need a face scan`, accepted immediately with no
prompt. Say: "Raising the limit needed a signature from the device. Lowering it did not, because
the moment you notice something wrong is the moment you must be able to clamp down." The node is
back at the scripted rule with nothing spent; `scripts/preflight.sh` is green again.

What the passkey step does and does not prove, if you are asked: the contract verifies that the
holder of a registered credential signed this exact challenge and that the authenticator asserted
user verification. It cannot prove the credential is hardware-backed, because there is no
attestation; so it is only as strong as registration: the first credential is registered by the admin alone, and every later one needs a signature from one that already exists.

## If something goes wrong

| What you see | What it means | What to do |
| --- | --- | --- |
| A card says "could not reach the chain" | The agent could not confirm the send. It is not a refusal. | Wait a few seconds; the card settles from the chain's log or the transaction hash. |
| A card says REFUSED but you expected ALLOWED | Read the code. 6 means the budget is spent. | `scripts/preflight.sh` tells you what is left; `reset-demo.sh` refills it. |
| The agent answers with a question | The sentence is outside the grammar. | Type exactly the sentence in `safe-phrasings.md`. |
| `preflight.sh` fails on the human gate | No real-device credential has been named, or it has never signed. | Register it, record it in `deployments/testnet.json` (`credentials`), run `reset-demo.sh` with it, set `REAL_DEVICE_CREDENTIAL_ID`. |

## Setting up a deployment

What the scripts cover and what they do not. Names below are the ones in `deployments/testnet.json`.

1. Create the accounts (the faucet gives each 10 NEAR): admin, wallet, budget node, token, and two
   payees. The two agents are sub-accounts of the budget node, created by it
   (`alpha.<budget-node>`, `beta.<budget-node>`). The admin must differ from the wallet.
2. Build and deploy: `scripts/build-contract.sh test-token` and deploy it to the token account with
   `new {owner_id, total_supply, decimals: 6}`, then `storage_deposit` for the wallet and every payee
   and `ft_transfer` the funding amount to the wallet. Then `scripts/deploy.sh <wallet> <admin> <token> testnet`.
3. Register at least two credentials with `scripts/register-credential.sh testnet <credential.json>`
   (the JSON `tools/capture-assertion.html` saves after step 1 works as it is). **The first one is
   the real device, and it is the bootstrap**: the admin registers it alone, because nothing exists
   yet to sign for it. That is the one act of trust in the design; do it on a machine you trust. The
   second is a second device or a recovery credential kept somewhere else, and it needs a signature
   from the first (the script prints a challenge and waits for a face scan): **the admin key alone
   cannot add a credential.** Removal is not gated, so **if every credential is lost the funds are
   stuck for good** and nobody can add a replacement.
4. Give each agent its key: the agent generates its keypair and hands over only the public key.
   `scripts/grant-agent-key.sh <wallet> <agent-account> <ed25519:public-key> testnet`. The agent's
   secret goes in `~/.leash-testnet/akf-<name>.json`, mode 600.
5. Freeze the wallet: `scripts/freeze.sh <wallet> testnet --yes-i-mean-it`. Irreversible.
6. Record the accounts in `deployments/testnet.json` (including `funded_wallet_balance`, the base
   units you funded the wallet with, and `credentials`: `[{"id": ..., "kind": "DEVICE ..." or "SOFTWARE ..."}]` for every registered credential **in the order they were registered, real device first**; preflight refuses anything else, because the first credential is the only one the admin key can add alone) and `agent/vendors.json`. The tests read both files, so nothing else needs editing.
7. Run the test suites, then the steps under "Before you record".

The first rule for the budget node is applied by `reset-demo.sh`, not by hand, so the rule
preflight checks and the rule that is applied are the same file.
