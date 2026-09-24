# Upstream proxy demo

A self-contained, offline end-to-end walkthrough of [upstream proxies](../../docs/learn/upstream-proxies.mdx). It starts three processes on loopback — a stand-in upstream API, a logging egress proxy, and the Agent Vault broker — then walks a single request through every state the feature can be in.

Nothing touches the network and nothing on your machine is modified: the broker runs with an isolated `HOME` (fresh SQLite database and CA) inside a temporary directory.

## What it proves

| Step | Assertion |
| --- | --- |
| 5 | With no profile, brokered requests dial the target directly. |
| 6 | An instance default profile routes the same request through the proxy. |
| 7 | `no_proxy` lets a matching target bypass the proxy again. |
| 8 | `fail_closed` refuses the request (502) when the proxy is unreachable — no silent fallback. |
| 9 | `fail_open` lets that request through by dialling directly. |
| 10 | Services reference profiles by name; unknown names are rejected, and a referenced profile cannot be deleted. |

The evidence is the proxy's own request log: step 6 records lines there, step 7 deliberately records none, and step 9 succeeds while the proxy is still down.

## Requirements

- Go 1.25+ (or an `agent-vault` binary already on `PATH`)
- Python 3 (standard library only)
- `curl`

## Run

```bash
cd examples/upstream-proxy-demo
./run.sh
```

Ports used: `14331` (control plane), `14332` (MITM proxy), `13128` (demo egress proxy), `18099` (demo target). All background processes are stopped on exit.

## Expected output

<details open>
<summary>Full run (abbreviated paths)</summary>

```
0. Building the broker
  ✓ built from source

1. Starting a stand-in upstream target on 127.0.0.1:18099
  ✓ target serves GET / (200)

2. Starting the logging egress proxy on 127.0.0.1:13128
  ✓ proxy forwards requests and logs them to egress-proxy.log

3. Starting the broker (ports 14331 / 14332)
  ✓ broker ready (isolated HOME=/tmp/tmp.XXXXXXXX)

4. Registering the owner and minting an agent token
  ✓ owner registered (first user becomes instance owner)
  ✓ vault-scoped agent token minted

5. Baseline: with no profile, requests dial the target directly
  ✓ brokered request succeeded (200) without touching the egress proxy

6. Creating the instance default profile 'corp-egress'
  ✓ profile created (scheme=http, host=127.0.0.1:13128, on_failure=fail_closed, is_default=true)
  ✓ request succeeded (200) and the proxy logged 1 new request(s)
  proxy log: GET http://127.0.0.1:18099/ -> 200

7. no_proxy lets a target bypass the profile
  ✓ request succeeded (200) while bypassing the proxy
  ✓ bypass cleared

8. fail_closed when the proxy is unreachable
  ✓ proxy down: broker returned 502 (no silent fallback to a direct dial)

9. fail_open lets the same request through
  ✓ request succeeded (200) by falling back to a direct dial
  policy restored to fail_closed

10. Services reference profiles by name
  ✓ unknown profile reference rejected: {"error":"service \"demo-api\" references unknown upstream proxy \"does-not-exist\""}
  ✓ service 'demo-api' now references corp-egress
  ✓ delete refused while referenced: {"error":"Upstream proxy \"corp-egress\" is referenced by 1 service(s): default/demo-api"}
  ✓ once unreferenced, the profile deletes cleanly
```

</details>

Each step fails the script loudly (`✗`) rather than continuing past a broken assumption. Failed runs print the log directory of that run — `broker.log`, `egress-proxy.log`, and `target.log` are the useful ones.

## Files

| File | Purpose |
| --- | --- |
| `run.sh` | Orchestrates the whole flow: build, three processes, ten steps, cleanup. |
| `egress_proxy.py` | ~150-line logging HTTP proxy. Understands absolute-form requests and `CONNECT`, forwards them, and appends one line per request to its log file — the demo's source of truth. |

## Notes for adapting this to a real proxy

- `AGENT_VAULT_ALLOW_PRIVATE_RANGES=true` is set only because every address in the demo is loopback. A real deployment needs neither that nor `-A` handling — leave private-range blocking on.
- Replace `egress_proxy.py` with your real proxy and set `scheme`/`host` to it; if it terminates TLS with a private CA, paste that certificate into the profile's **CA certificate (PEM)** field.
- Steps 8 and 9 are the ones worth rehearsing before a cutover: stop the proxy, confirm the broker's behaviour under `fail_closed`, then decide whether `fail_open` is acceptable for that window.
