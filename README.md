# Stopping RCE: you can't execute what you don't have

![A malicious .zip tries to plant a root program or overwrite a file another service trusts; two Cosmonic sandboxes with scoped grants block every move — across both zip-crate CVEs.](docs/images/zip-sandbox-rce-hero.png)

This is a live demo of **mitigating Remote Code Execution (RCE)** exploits with a secure,
deny-by-default, isolated **Cosmonic Sandbox**. It takes a popular Rust library for opening `.zip`
files — one with **two real CVEs a week apart** — runs the *exact same vulnerable code* inside the
sandbox, and shows both attacks fail anyway. **Nothing is patched.**

- **[RUSTSEC-2026-0367](https://rustsec.org/advisories/RUSTSEC-2026-0367.html)** (setuid, **CVSS 7.3**) —
  the extractor copies setuid/setgid/sticky bits through verbatim, so a crafted zip can plant a file
  that runs with **root powers**.
- **[CVE-2026-115905](https://www.cve.org/CVERecord?id=CVE-2026-115905)** (zip cloaking, **CVSS 10.0**) —
  an archive shows one benign filename to a scanner and hands a *different* path to a streaming
  extractor, silently **overwriting a file another service trusts**.

> **The one idea.** A sandbox doesn't have to be clever enough to *spot* the attack. It starts with
> **nothing** and only hands the code the specific powers you grant it — the right to touch one
> scratch folder, and nothing else. You can't execute what you don't have. Read
> **[Choosing an agent sandbox](https://cosmonic.com/ai-sandbox/choosing-an-agent-sandbox/)** and the
> **[principles of secure platforms](https://cosmonic.com/ai-sandbox/principles/)** (deny-by-default,
> least authority, [policy enforcement points](https://cosmonic.com/ai-sandbox/principles/policy-enforcement-points/),
> [capabilities over ambient authority](https://cosmonic.com/ai-sandbox/capabilities/)).

**Live UI:** <http://zip-sandbox.localhost:8200/> once deployed.

---

## How it's built — two components, two disjoint grant sets

The demo is **one workload with two components**, each its own sandbox, wired by a **live p3
`stream<u8>`** that crosses between them inside the host:

| Component (in [`deploy/zip-sandbox.workload.yaml`](deploy/zip-sandbox.workload.yaml)) | Filesystem | Network | HTTP |
|----------|------------|---------|------|
| `web` (the UI + entrypoint) | ❌ none | ❌ deny-all | exports `wasi:http/handler` |
| `extractor` (the unzip) | ✅ `/tmp/unzip` only | ❌ deny-all | none — reachable only via the link |

Those grants *are* the mitigation: the extractor's one `/tmp/unzip` volume is its only filesystem
preopen, `allowedHosts: []` on both means neither can phone home, and the extractor has no HTTP
surface at all — the host auto-links `web`'s import of `cosmonic:zip-demo/extraction` to the
extractor's export, and the untrusted archive travels between them as a live stream. The browser
talks to one origin; the component boundary is crossed inside the host.

The two components are published to **GitHub Container Registry**:

- `ghcr.io/cosmonic-labs/demo-zip-rce-sandbox/web`
- `ghcr.io/cosmonic-labs/demo-zip-rce-sandbox/extractor`

---

## Step 1 — Install Cosmonic Desktop

Cosmonic Desktop is a local wasmCloud host: it runs WebAssembly components as sandboxed workloads on
your own machine.

- **Download / join the beta:** <https://cosmonic.com/desktop/>
- **Docs:** <https://cosmonic.com/docs/desktop/>

Once it's running it listens on `127.0.0.1:8200` and routes workloads by the HTTP `Host` header.

## Step 2 — Deploy the workload (pulls from ghcr)

[`deploy/zip-sandbox.workload.yaml`](deploy/zip-sandbox.workload.yaml) pins both components by digest
on ghcr, so applying it pulls the images straight from the registry — **no local build required.**

> ⚠️ **One gotcha.** The extractor needs its `/tmp/unzip` volume, and the *quick* deploy paths
> (`cosmonic dev`, publish drafts, the Desktop UI's "paste an image link" flow) generate a starter
> spec from the image alone and **leave the `volumes` section out** — deployed that way it returns
> `"sandbox unavailable"`. Apply the durable manifest (which keeps the volume) by one of the routes below.

### Route A — an AI assistant over MCP *(recommended)*

Cosmonic Desktop ships an MCP server (on by default). Connect it once in **Desktop → Settings → MCP
Server** (see [Connect coding agents](https://cosmonic.com/docs/desktop/coding-agents/)) from Claude
Code, Claude Desktop, Codex, Cursor or Gemini CLI, then ask:

> "Apply `deploy/zip-sandbox.workload.yaml` to Cosmonic Desktop, then show me its status."

It's applied verbatim — nothing drafts the volume away.

### Route B — drop the manifest into Desktop's state directory

Copy the manifest to `workloads/default/zip-sandbox.yaml` under the state directory (`cosmonicd paths`
prints it). Desktop reconciles it.

### Confirm it's healthy

```
cosmonic_workload_list        # zip-sandbox: running, restarts: 0 (web + extractor)
```

## Step 3 — Fire the attacks

Open the UI and click a red button — each streams a genuinely malicious `zip 8.6.0` archive into the
sandbox:

- **UI:** <http://zip-sandbox.localhost:8200/>
- **Host-header form (any shell):** `curl -H 'Host: zip-sandbox.localhost' http://127.0.0.1:8200/`

| Button | Vulnerability | What the archive does |
|--------|---------------|-----------------------|
| **Bug 1** | RUSTSEC-2026-0367 · setuid · CVSS 7.3 | setuid / setgid / sticky mode bits |
| **Bug 2** | CWE-22 · zip-slip / path traversal · CVSS 8.1 | `../` names that try to write outside the tree |
| **Bug 3** | CVE-2026-115905 · zip cloaking · CVSS 10.0 | benign central-dir name hiding the real local-header path |
| **Run all** | all three at once | one archive carrying every attack |

```bash
B=http://127.0.0.1:8200
# modes: suid (default) | slip | cloak | all
curl -s -H 'Host: zip-sandbox.localhost' "$B/run?mode=all" | python3 -m json.tool
# upload your own zip:
curl -s -H 'Host: zip-sandbox.localhost' -H 'content-type: application/zip' \
     --data-binary @your.zip "$B/run" | python3 -m json.tool
```

A contained run reads, e.g.:

```
MITIGATED: 3 privileged (setuid/setgid/sticky) entries in the archive, 0 applied;
3 zip-slip paths refused; 1 cloaked entry (CVE-2026-115905) honored but confined.
Everything stayed inside /tmp/unzip.
```

---

## Under the hood — why the sandbox neutralizes both

**Bug 1 — the setuid bits.** [RUSTSEC-2026-0367](https://rustsec.org/advisories/RUSTSEC-2026-0367.html)
(GHSA-vv5m-jxxh-4627, CWE-732, CVSS 7.3), affecting the Rust `zip` crate at `<= 9.0.0-pre3`. On Unix a
**setuid** file runs with the privileges of its *owner*, not whoever launched it — a classic privilege
-escalation primitive. A ZIP can store those bits per entry, and on extract the crate copies them
through **verbatim instead of masking them off** (its *writer* masks with `& 0o777` — one half closes
the door the other leaves open). An attacker waits for a privileged process (an installer, a CI job, a
root container build) to extract a crafted entry and lands a setuid-root file. Patched in `zip 9.0.0`.

**Bug 2 — zip cloaking.** [CVE-2026-115905](https://www.cve.org/CVERecord?id=CVE-2026-115905)
(GHSA-m665-v7pm-7grj, CWE-436 / CWE-20, **CVSS 10.0**), affecting the crate **through 9.0.4**. A ZIP
stores each entry's name twice — central directory and local file header. `ZipArchive` trusts the
central directory; a streaming reader trusts the local header, and the crate never reconciles the two.
A crafted archive advertises `release-notes.txt` to a scanner while a streaming extractor writes
`home/you/.ssh/authorized_keys` — a path the scanner never saw. On a service that extracts into its own
tree that's an arbitrary file overwrite, the road to RCE. Patched in `zip 9.0.5`.

**The mechanism.** The extractor is compiled to `wasm32-wasip2`, which is **not a Unix target**, so the
crate's permission-setting code — guarded by `#[cfg(unix)]`, the exact condition it uses to apply those
bits — is **compiled out entirely**. The malicious bit still arrives (the report surfaces it) but no
code path can apply it. On top of that the workload is granted exactly one directory and no network, so
the zip-slip and phone-home surfaces fail too. The cloaking bug is different: the sandbox does **not**
fix the parser differential (that's a crate bug, present in wasm too) — it removes the *consequence*.
The extractor's only writable path is the single `/tmp/unzip` preopen, so even the honored cloak path
can only ever land on a throwaway file in an ephemeral, per-request directory, never on a file the host
depends on.

> **Everything here is non-weaponized.** The crafted archives contain only inert text files. We set the
> hostile permission *metadata bits* and hostile entry *names* and observe what the runtime does with
> them. No executable, no root access, and no actual privilege escalation is ever performed.

---

## Build from source (optional)

The deploy step above needs none of this — it pulls prebuilt images from ghcr. To rebuild:

```bash
# web component
cd cosmonic-app/web && cargo build --target wasm32-wasip2 --release
# extractor component
cd ../extractor && cargo build --target wasm32-wasip2 --release
# publish (bump the tag, then update the digest in deploy/zip-sandbox.workload.yaml)
wash oci push ghcr.io/cosmonic-labs/demo-zip-rce-sandbox/web:<tag> \
  cosmonic-app/web/target/wasm32-wasip2/release/zip_sandbox_web.wasm
```

Cosmonic Desktop's Preflight doctor provisions `rustc`, the `wasm32-wasip2` target, and `wash`.

---

## The takeaway

**Defense in depth** is both:

1. **Patch** — upgrade to `zip >= 9.0.5`, which masks the privileged bits (bug 1) and reconciles the dual headers (bug 2).
2. **Contain** — run anything that extracts, parses, or executes untrusted input inside a
   capability-scoped WASM sandbox, so a vulnerable dependency (**known or not-yet-known**) cannot apply a
   malicious bit, escape its directory, or reach anything you didn't grant.

Further reading:
[Choosing an agent sandbox](https://cosmonic.com/ai-sandbox/choosing-an-agent-sandbox/) ·
[Principles](https://cosmonic.com/ai-sandbox/principles/) ·
[Deny by default](https://cosmonic.com/ai-sandbox/principles/deny-by-default/) ·
[Least authority](https://cosmonic.com/ai-sandbox/least-privilege-ai-agents/) ·
[Capabilities](https://cosmonic.com/ai-sandbox/capabilities/)

---

### Repo layout

```
.
├── README.md                          ← this walkthrough
├── deploy/
│   └── zip-sandbox.workload.yaml      ← one workload, two components, linked by a p3 stream (ghcr images)
├── cosmonic-app/
│   ├── wit/                           ←   cosmonic:zip-demo/extraction (the live-stream link)
│   ├── web/                           ←   the UI component (crafts + streams the archive in)
│   └── extractor/                     ←   the unzip component (the vulnerable crate, exports extraction)
└── docs/images/                       ← the hero banner
```
