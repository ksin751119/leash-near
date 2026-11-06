// Sending one `spend`, signed as the agent's own account.
//
// The function-call key lives on AGENT_ACCOUNT with the wallet as receiver and only `spend`
// allowed: the contract derives the budget from the caller's id, so the transaction's signer
// must be the agent account itself. 60 TGas, because spend needs ~40 and 30 fails; zero
// deposit, because a function-call key cannot attach one.
//
// Signing goes through near-cli with the key FILE's path in argv. The key itself is never in
// argv or the environment.
//
// `spend` never panics on a policy refusal: the transaction succeeds, no money moves, and the
// outcome is in the return value (and, authoritatively, on chain). So a zero exit code says
// nothing about whether anyone was paid.
import { execFile } from "node:child_process";
import { promisify } from "node:util";

const run = promisify(execFile);

const TX_RE = /Transaction ID:\s*([1-9A-HJ-NP-Za-km-z]{43,44})/;

// near-cli prints the return value as a pretty JSON object after "Function execution return
// value:"; take the first balanced object after it.
export function parseSpendOutput(text) {
  const tx = TX_RE.exec(text)?.[1] ?? null;
  const at = text.indexOf("Function execution return value");
  let outcome = null;
  if (at >= 0) {
    const start = text.indexOf("{", at);
    if (start >= 0) {
      let depth = 0;
      for (let i = start; i < text.length; i++) {
        if (text[i] === "{") depth++;
        else if (text[i] === "}" && --depth === 0) {
          try { outcome = JSON.parse(text.slice(start, i + 1)); } catch { /* left null */ }
          break;
        }
      }
    }
  }
  return { txHash: tx, outcome };
}

export async function sendSpend({ network = "testnet", wallet, agent, keyFile, token, payee, amount }) {
  const args = [
    "contract", "call-function", "as-transaction", wallet, "spend",
    "json-args", JSON.stringify({ token, payee, amount: String(amount) }),
    "prepaid-gas", "60 Tgas", "attached-deposit", "0 NEAR",
    "sign-as", agent, "network-config", network,
    "sign-with-access-key-file", keyFile, "send",
  ];
  const { stdout, stderr } = await run(process.env.NEAR_BIN || "near", args, { timeout: 90_000, maxBuffer: 4_000_000 });
  return parseSpendOutput(`${stdout}\n${stderr}`);
}
