// Plain JSON-RPC reads, in the browser or in Node. No signing, no keys, no indexer, no API
// key. A view call is free and synchronous, so polling it every two seconds cannot be rate
// limited by anything this project controls.
// Not rpc.testnet.near.org: it sends no CORS headers, so a browser cannot call it, and it
// answered 429 on 2026-11-06. fastnear allows any origin.
export const DEFAULT_RPC = "https://test.rpc.fastnear.com";

async function rpc(url, params, timeoutMs = 4000) {
  const res = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "query", params }),
    signal: AbortSignal.timeout(timeoutMs),
  });
  const body = await res.json();
  if (body.error || body.result?.error) {
    throw new Error(JSON.stringify(body.error ?? body.result.error).slice(0, 200));
  }
  return body.result;
}

export async function callView(url, account, method, args = {}) {
  const r = await rpc(url, {
    request_type: "call_function",
    finality: "optimistic",
    account_id: account,
    method_name: method,
    args_base64: btoa(JSON.stringify(args)),
  });
  return JSON.parse(new TextDecoder().decode(new Uint8Array(r.result)));
}

// `view_access_key_list` on the account itself. There is no contract method for this and
// there must not be one: no NEAR host function can enumerate an account's own keys.
export const accessKeys = (url, account) =>
  rpc(url, { request_type: "view_access_key_list", finality: "optimistic", account_id: account });
