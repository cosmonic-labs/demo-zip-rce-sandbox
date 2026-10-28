//! zip-crate sandbox demo — the EXTRACTOR component (Cosmonic Desktop, p3).
//! Contains RUSTSEC-2026-0367 (setuid) and surfaces CVE-2026-115905 (cloaking).
//!
//! One job, exported over ONE custom p3 interface: accept the untrusted archive
//! as a live `stream<u8>`, drain it into the single preopened directory
//! `/tmp/unzip`, and unzip it there with the SAME vulnerable `zip` 8.6.0 crate
//! as the native demo. It returns a JSON report of what the archive asked for
//! versus what the sandbox allowed.
//!
//! The archive arrives as a stream handle linked in from the `web` component at
//! runtime — the host passes the handle guest-to-guest (resource-identity
//! passthrough), so this component reads the bytes straight off the linker.
//! This is the extractor half of wasmCloud's `integration_p3_streams` pattern.
//!
//! This component is deliberately starved: its only grant is the one tmp
//! directory (filesystem). `allowedHosts: []` means no network, and it exports
//! no HTTP, so nothing outside the host can reach it directly. The `web`
//! component has the opposite shape (HTTP + UI, no filesystem). Two sandboxes,
//! two disjoint grant sets, one live stream between them.

mod sandbox;

wit_bindgen::generate!({
    world: "extractor",
    path: "../wit",
    // `extract` is declared `async` in the WIT, which drives async codegen for
    // it alone; the sync p2 wasi imports std pulls in stay sync. (A blanket
    // `async: true` here would wrongly mark those async and fail to encode.)
    // Keep this crate's component-type section from colliding with any other.
    type_section_suffix: "zip-demo-extractor",
    generate_all,
});

use exports::cosmonic::zip_demo::extraction::Guest;
use wit_bindgen::{StreamReader, StreamResult};

struct Component;

export!(Component);

impl Guest for Component {
    /// Drain the live archive stream, then run the vulnerable extraction inside
    /// the sandbox and return the JSON verdict.
    ///
    /// We read the whole stream before parsing because a ZIP's central
    /// directory lives at the *end* of the file — you cannot unzip a prefix.
    /// The stream is still the real interface: the bytes cross the component
    /// linker live, and this component buffers them only after they arrive.
    async fn extract(archive: StreamReader<u8>) -> String {
        let bytes = drain(archive).await;
        let report = sandbox::extract_into_sandbox(&bytes);
        serde_json::to_string(&report)
            .unwrap_or_else(|e| format!("{{\"error\":\"serialize failed: {e}\"}}"))
    }
}

/// Read a p3 `stream<u8>` to completion into one buffer. Loops until the writer
/// drops its end (`StreamResult::Dropped`), mirroring the read loop the `wasip3`
/// HTTP body reader uses.
async fn drain(mut reader: StreamReader<u8>) -> Vec<u8> {
    const CHUNK: usize = 64 * 1024;
    let mut buf: Vec<u8> = Vec::new();
    loop {
        let (result, chunk) = reader.read(Vec::with_capacity(CHUNK)).await;
        buf.extend_from_slice(&chunk);
        match result {
            // More bytes may follow — keep reading.
            StreamResult::Complete(_) => continue,
            // Writer end dropped: the archive is fully received.
            StreamResult::Dropped => break,
            // Read cancelled: stop with whatever we have.
            StreamResult::Cancelled => break,
        }
    }
    buf
}
