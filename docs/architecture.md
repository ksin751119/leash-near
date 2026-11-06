# Architecture

Leash is one NEAR contract that holds an NEP-141 balance and decides every payment out of it,
two agent processes that ask it to pay, and a page that reads what it decided. This file is how
the pieces fit; the README says what each claim rests on, and `docs/superpowers/specs/` has the
reasoning behind each decision.

## The accounts

```
admin        a human's full-access key. Writes rules, creates agent accounts, registers the FIRST credential.
             Cannot move money, cannot widen a rule, and cannot register a second credential alone.
wallet       holds the token and runs the contract. After freeze.sh it has NO keys of any kind:
             nobody can sign as it and its code can never change.
budget node  a name and a parent. Carries the rule. Has no role at runtime except its id.
 ├─ alpha    agent 1: ONE function-call key, receiver = wallet, methods = ["spend"], capped allowance
 └─ beta     agent 2: the same, its own key
```

The agent's key is on the agent's own account, not on the wallet. `spend` finds the budget by
taking `predecessor_id` and dropping everything up to the first `.` (`alpha.node` becomes `node`),
and a key on the wallet would sign as the wallet and be refused with code 1. Everything the key
cannot do (call the token, call any other method, attach a deposit, add keys, deploy) is refused
by the NEAR protocol before any contract code runs; the contract's own checks decide only what
`spend` itself may do. Two agents share a budget because their accounts share a parent, and for
no other reason: they have no channel to each other.

## One payment

```
agent ──spend(token, payee, amount)──▶ wallet
   1  caller derives to a node with a rule?     no → refuse 1
   2  account or node paused?                   yes → refuse 2
   3  token is the rule's token?                no → refuse 3
   4  payee on the allow-list?                  no → refuse 4
   5  amount over the per-transaction limit?    yes → refuse 5
   6  spent + amount over the period limit?     yes → refuse 6
   7  outside the active window?                yes → refuse 7
   refused → write the decision, emit an event, RETURN NORMALLY
   allowed → reserve the amount, ft_transfer, settle in the callback
```

A refusal is a **successful transaction** that records the decision and returns it. If the
contract panicked, NEAR would roll the transaction back, including the record of why, and the
chain would hold a failed transaction and no explanation. So an explorer shows a transaction with no failed receipt, and a
`leash: refused` log, next to a payment that did not happen; the page says so beside every refusal. The same applies to the
allowed path in a different way: NEAR rolls back per receipt, not per transaction, so a
transaction-level failure after `ft_transfer` ran does not mean no money moved, and the agent
never says it does without reading the receipts.

The amount is reserved before `ft_transfer` is dispatched, so a second agent arriving while the
transfer is in flight sees the reservation. If the transfer fails, the callback releases it, but
only into the same window and the same epoch it was taken from (a reservation from before a
widening is not handed back against the new ledger).

Decisions go to two bounded rings of twenty and four. `spend` is open to any caller on NEAR (the
rule for the derived node is the whole of the authorisation), so a stranger's refusal must not
evict a real agent's decision: callers with no rule write only to the small ring.

## Rules and the passkey gate

A rule is a token, a per-transaction limit, a period limit and length, an active window, a payee
list, and a paused flag. `set_rule` is admin-only, and the contract classifies the change against the
rule in force: if any field loosens, the call needs an assertion from a registered credential; if
none does, it needs none. A new node, an empty-to-something change, a swapped payee, a shorter
period and an unpause are all loosenings. The brake (tightening) is never gated.

An assertion is the WebAuthn `get` response. The contract recomputes the expected challenge as
`SHA-256(action ‖ payload ‖ nonce ‖ this contract's account id)`, each part length-prefixed, and
checks the credential's P-256 signature over `authenticator_data ‖ SHA-256(client_data_json)`, that
the challenge in the client data is the expected one, that the type is `webauthn.get`, and that the
authenticator set the user-verified bit. The nonce advances on use. Five actions have five tags
(`set_rule`, `add_payee`, `unpause`, `withdraw`, `register_credential`), so an assertion for one cannot be redirected to
another.

An accepted widening is the only thing that resets a node's spend ledger (it bumps the epoch and
starts a new window). Re-applying an identical rule does nothing to the ledger, because that used to
be a free, ungated budget refill. This is why a demo reset after a take needs a face scan.

What this proves is narrow. It proves the holder of a registered credential signed this exact
challenge and that the authenticator asserted user verification. It cannot prove the credential is
hardware-backed (there is no attestation, and synced passkeys attest `none`), so the guarantee is
only as strong as registration. The first credential is registered by the admin alone (the
bootstrap, the one unavoidable act of trust); every later one needs the admin and an assertion from a
registered credential, under its own action tag over the new key. Each credential is stamped with its registration order (the bootstrap is sequence 0, numbers are never reused), which is how preflight reads "who was first" from the chain. Otherwise a stolen admin key could
mint its own credential and sign a widening with it. Removal is ungated, so losing every credential
strands the funds. See the README for the full wording.

P-256 is not a NEAR host function, so the curve arithmetic runs in the wasm: 33.8 TGas of the 300
a transaction gets.

## The agents

Each agent is one Node process (`agent/loop.mjs`) with one key file, holding no key that signs as
anything but its own account. It parses an instruction with a closed grammar (`agent/parse.mjs`: two
sentence shapes, anything else gets a question back), predicts the answer from the chain's views
(`agent/decide.mjs`, cross-checked against the contract's own table by `contract-cases.json`), says
what it understood on screen, signs and sends `spend` itself with 60 TGas attached, and reconciles
the result against the chain's decision log. The chain is the authority on what happened; the agent
never settles a card from a broadcast error.

## The page

`web/demo.html` polls each agent's `/state` every two seconds and renders it. It makes no chain
call of its own except two key-list queries. There is no indexer.

## The RPC budget

No indexer, view calls only. At idle the whole system (two agents and the page) makes about 0.77
RPC calls per second, measured with a counting proxy for 110 seconds against
`test.rpc.fastnear.com`: 85 calls, of which 36 `decision_log`, 19 `node_record`, 14 `is_paused`
and 16 `view_access_key_list`. The previous version of this project used an indexer and it hit a
rate limit mid-recording. Public NEAR RPC endpoints rate-limit by IP, and a 429 carries no CORS
header, so a browser reports it as a CORS failure. So reads are budgeted, cached with a time to
live per method, shared between concurrent requests, tried across several endpoints in order, and
served stale (and marked stale) while an endpoint is limited rather than retried harder.
`rpc.testnet.near.org` is left out on purpose: it answers 429 to a "deprecated" notice. Details in
`agent/chain.mjs`.

## The scripts

| Script | What it is for |
| --- | --- |
| `build-contract.sh` | The only way to build the wasm. Sets `--cfg near`, refuses a wasm without it. |
| `deploy.sh` | Deploy and `new`. Refuses admin equal to wallet. |
| `grant-agent-key.sh` | Put the spend-only key on an agent account, read it back, delete full-access keys. |
| `freeze.sh` | Delete the wallet's full-access key. Irreversible. |
| `register-credential.sh` | Register a credential: the first by the admin alone, later ones with a signature from an existing one. |
| `reset-demo.sh` | Bring the budget node to the scripted rule with nothing spent; one face scan per widening. |
| `preflight.sh` | Read-only readiness check, ends in READY or NOT ready. |
| `demo-beats.json`, `demo-rule.sh` | The scripted demo as data, shared by reset and preflight. |

`preflight.sh` and `reset-demo.sh` are tested against a fake chain and a fake `near`
(`scripts/*.test.mjs`), including the cases where they must fail.
