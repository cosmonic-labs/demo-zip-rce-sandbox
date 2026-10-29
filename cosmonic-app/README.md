# Part 2 — the same vuln, mitigated, split across two components linked by a live p3 stream

The branded demo. It runs the **same vulnerable `zip` 8.6.0 crate** as
[Part 1](../native-demo/README.md) — carrying **both** bugs, RUSTSEC-2026-0367 (setuid) and
[CVE-2026-115905](https://www.cve.org/CVERecord?id=CVE-2026-115905) (zip cloaking, CVSS 10) — compiled
to `wasm32-wasip2`, but split into **two separate WebAssembly components** in **one workload** — each its own sandbox with its own capability grants,
wired together by a **live p3 `stream<u8>`** that crosses the component boundary inside the host:

| Component | Directory | Filesystem | Network | HTTP | Role |
|-----------|-----------|------------|---------|------|------|
| **web** | [`web/`](web/) | ❌ none | ❌ deny-all | exports `wasi:http/handler` | Serves the branded UI. Crafts the archive and streams it across the link. |
| **extractor** | [`extractor/`](extractor/) | ✅ `/tmp/unzip` only | ❌ deny-all | none (linked only) | Does the actual unzip with the vulnerable crate. Reachable only via the link. |

When the page calls `/run`, `web` opens a `stream<u8>`, feeds the crafted archive into it, and hands
the read end to `extractor` through the host's runtime link
(`cosmonic:zip-demo/extraction.extract(stream<u8>) -> string`). The stream handle is passed
**guest-to-guest inside the host** — resource-identity passthrough, never buffered at the linker.
Two components, two disjoint grant sets, one live stream between them. This is the
[`integration_p3_streams`](https://github.com/wasmCloud/wasmCloud/blob/main/crates/wash-runtime/tests/integration_p3_streams.rs)
pattern from wasmCloud, applied to a real isolation boundary.

> We deliberately did **not** upgrade to the patched `zip 9.0.5`, and we did **not** mask the bits in
> our own code. `extractor` reads the raw mode with the exact vulnerable accessor
> (`ZipFile::unix_mode()`) and surfaces the central-dir/local-header differential with
> `read_zipfile_from_stream`. The point is to prove the **sandbox** contains both anyway.

## Why it's the strong-isolation story

A single composed component (`wac plug`) would merge both halves into **one** grant set. Two
components **auto-linked in one workload** keep their grants **disjoint** — the component that holds
the untrusted bytes' only filesystem authority (`/tmp/unzip`) is a different sandbox from the one
with the network-facing UI, and the live stream is the only thing that crosses between them.

1. **No privileged-bit semantics.** `wasm32-wasip2` isn't a Unix target, so the crate's `#[cfg(unix)]`
   permission code is compiled out. The malicious `0o104755` mode arrives — the report surfaces it —
   but nothing can apply it.
2. **Capability confinement.** `extractor`'s only filesystem authority is the single preopened
   `/tmp/unzip`. A zip-slip symlink or absolute path can't escape (the crate's symlink code is
   compiled out, so links land as plain files); `/etc`, `$HOME`, `..` don't exist from
   inside. The report runs these as live escape probes (they fail with `os error 44`).
3. **Deny-all egress.** Both components ship `allowedHosts: []` — neither can phone home.
4. **No filesystem on `web` at all, and no HTTP on `extractor` at all.** `web` imports no
   `wasi:filesystem`; `extractor` exports no `wasi:http` and has no hostname — nothing outside the
   host can reach it. Confirm with `cosmonic_image_inspect`.
5. **Cloaking is contained, not fixed.** The parser differential of CVE-2026-115905 still exists in
   the crate (the report flags the cloaked entry), but because `/tmp/unzip` is the only writable path,
   the hidden write can only ever land on a throwaway file in an ephemeral, per-request directory —
   never on a file the host relies on. Confinement turns a CVSS 10 overwrite into a non-event.

## Live now

- **UI + API:** http://zip-sandbox.localhost:8200/
- `GET /run` — craft the 6-entry suite, stream it across the link, return the JSON verdict.
- `GET /run?mode=single` — same, with the 2-entry archive.
- `GET /run?mode=cloak` — stream the cloaked archive (CVE-2026-115905); the verdict flags the hidden entry.
- `POST /run` (body = a `.zip`) — stream an uploaded archive across the link.

Open the UI, click **▶ Run bug 1 (setuid suite)** or **▶ Run bug 2 (zip cloaking)**, and read the verdict:

```
✓ MITIGATED: 3 privileged (setuid/setgid/sticky) entries in the archive, 0 applied.
  Extraction stayed inside /tmp/unzip; 2 of 2 escape attempts were refused.
```

### Command-line check

```bash
curl -s -H 'Host: zip-sandbox.localhost' http://127.0.0.1:8200/run | python3 -m json.tool
# or: tests/validate-live.sh
```

## The interface (WIT)

[`wit/zip-demo.wit`](wit/zip-demo.wit) defines the one private interface the two components share:

```wit
package cosmonic:zip-demo@0.1.0;
interface extraction {
  extract: async func(archive: stream<u8>) -> string;
}
world extractor { export extraction; }   // the unzip
world web       { import extraction; }    // the UI, streams the archive in
```

`extract` is declared **`async`** so its component func type carries the async flag — the
`[async-lower]`/`[async-lift]` canonical ABI that streams the handle across the linker requires an
async function type (a plain `func` taking a stream fails to encode). Each crate generates its half
with `wit_bindgen::generate!`; `web` also keeps the `wasip3` HTTP bindings for its entrypoint, so its
two component-type sections are kept distinct with `type_section_suffix`.

## Build & deploy

Two `wash` projects, one workload. Build, push, and apply the single durable Workload:

```bash
# build
(cd web && cargo build --target wasm32-wasip2 --release)
(cd extractor && cargo build --target wasm32-wasip2 --release)
# push (bump the tag on every rebuild)
wash oci push --insecure oci.localhost:8200/apps/zip-sandbox-web:0.2.1        web/target/wasm32-wasip2/release/zip_sandbox_web.wasm
wash oci push --insecure oci.localhost:8200/apps/zip-sandbox-extractor:0.2.0  extractor/target/wasm32-wasip2/release/zip_sandbox_extractor.wasm
# apply (update the digests in the manifest first):
#   cosmonic_workload_apply(../deploy/zip-sandbox.workload.yaml)
```

The manifest carries the `/tmp/unzip` volume on `extractor`, deny-all egress on both, and one
`wasi:http/handler` hostInterface (which binds to `web`, the only HTTP exporter). The `cosmonic dev`
loop and publish drafts strip the volume, so deploy the durable manifest in
[`../deploy/zip-sandbox.workload.yaml`](../deploy/zip-sandbox.workload.yaml), not dev.

## Layout

- `wit/zip-demo.wit` — the shared `cosmonic:zip-demo/extraction` interface (the live-stream link).
- `web/` — UI + crafted archives (`src/page.rs`, `src/archives.rs`, `src/lib.rs`). No zip crate, no disk.
- `extractor/` — the vulnerable extraction (`src/sandbox.rs`, `src/lib.rs`). The volume lives here.
- `../deploy/zip-sandbox.workload.yaml` — the single durable Workload (both components).
