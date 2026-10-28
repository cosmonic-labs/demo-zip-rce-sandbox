//! zip-crate sandbox demo — the WEB component (Cosmonic Desktop, p3).
//! Demonstrates RUSTSEC-2026-0367 (setuid) and CVE-2026-115905 (zip cloaking).
//!
//! Serves the branded UI and owns the crafted attack archives. It has NO
//! filesystem and NO network grants. When the page calls `/run`, this component
//! builds the crafted archive in memory, opens a live p3 `stream<u8>`, and hands
//! it to the SEPARATE `extractor` component through the host's runtime link —
//! `extraction::extract(stream<u8>) -> string`. The untrusted bytes stream
//! guest-to-guest across the linker; they are never written to this component's
//! (non-existent) disk, and the browser never talks to the extractor directly.
//!
//! This is the `web` half of wasmCloud's `integration_p3_streams` pattern: two
//! components in one workload, auto-linked, with a `stream<u8>` crossing the
//! dynamic linker intact.
//!
//! Routes:
//!   GET  /                -> the UI
//!   GET  /run?mode=suid   -> stream the setuid/setgid/sticky archive (Bug 1); default
//!   GET  /run?mode=slip   -> stream the zip-slip / path-traversal archive (Bug 2)
//!   GET  /run?mode=cloak  -> stream the cloaked archive (Bug 3, CVE-2026-115905)
//!   GET  /run?mode=all    -> stream the combined archive (Bug 4: every attack at once)
//!   GET  /suid.zip        -> download the Bug 1 archive (to inspect)
//!   GET  /slip.zip        -> download the Bug 2 archive (to inspect)
//!   GET  /cloak.zip       -> download the Bug 3 archive (to inspect)
//!   GET  /all.zip         -> download the Bug 4 combined archive (to inspect)
//!   GET  /health          -> "ok"

mod archives;
mod page;

/// The branded hero infographic (served at `/hero.png` for the page banner).
const HERO_PNG: &[u8] = include_bytes!("hero.png");

/// The Cosmonic icon mark, served at `/favicon.svg` as the browser-tab icon
/// (official purple #655DC6).
const FAVICON_SVG: &[u8] = br##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 38 42"><path fill="#655DC6" d="M17.47,32.38C15.36,26.74,12.59,24,6.92,21.89a.93.93,0,0,1,0-1.75c5.67-2.11,8.44-4.86,10.55-10.5a.93.93,0,0,1,1.76,0c1.7,5.7,3.67,9.57,16.62,9.82a.93.93,0,0,0,.94-.93V12.17a3.35,3.35,0,0,0-1.65-2.88L20.07.46a3.3,3.3,0,0,0-3.35,0L1.65,9.29A3.35,3.35,0,0,0,0,12.18V29.87a3.33,3.33,0,0,0,1.65,2.88l15.07,8.83a3.34,3.34,0,0,0,3.35,0l15.07-8.83a3.33,3.33,0,0,0,1.65-2.88V23.45a.93.93,0,0,0-.95-.93c-13,.25-14.91,4.12-16.61,9.81A.92.92,0,0,1,17.47,32.38Z"/></svg>"##;

// The runtime-link interface to the extractor. Import-only world: this
// generates the `extraction::extract` import binding (and the stream codegen)
// without touching the HTTP bindings the `wasip3` crate provides below. The
// type_section_suffix keeps its component-type section distinct from wasip3's.
mod zip_link {
    wit_bindgen::generate!({
        world: "web",
        path: "../wit",
        // `extract` is declared `async` in the WIT, which drives async codegen
        // for the import; the wasi imports stay sync. (See the extractor note.)
        type_section_suffix: "zip-demo-web",
        generate_all,
    });
}
use zip_link::cosmonic::zip_demo::extraction;

use http_body_util::BodyExt;
use wasip3::http::types::{ErrorCode, Fields, Method, Request, Response};
use wasip3::http_compat::{BodyWriter, IncomingRequestBody};

struct Component;

wasip3::http::service::export!(Component);

impl wasip3::exports::http::handler::Guest for Component {
    async fn handle(request: Request) -> Result<Response, ErrorCode> {
        let method = request.get_method();
        let path_q = request.get_path_with_query().unwrap_or_default();
        let (path, query) = match path_q.split_once('?') {
            Some((p, q)) => (p, q),
            None => (path_q.as_str(), ""),
        };

        match (&method, path) {
            (Method::Get, "/") | (Method::Get, "") => {
                respond(200, "text/html; charset=utf-8", page::PAGE.as_bytes().to_vec())
            }
            (Method::Get, "/health") => respond(200, "text/plain; charset=utf-8", b"ok\n".to_vec()),

            // THE demo path: craft the archive, stream it across the runtime
            // link to the extractor, and return the verdict the extractor
            // computed. No bytes touch this component's disk — it has none.
            (Method::Get, "/run") => {
                let zip = if query_has(query, "mode", "slip") {
                    // Bug 2: zip-slip / path traversal.
                    archives::craft_zipslip_zip()
                } else if query_has(query, "mode", "cloak") {
                    // Bug 3 (CVE-2026-115905): a cloaked archive.
                    archives::craft_cloak_zip()
                } else if query_has(query, "mode", "all") {
                    // Bug 4: every attack in one archive.
                    archives::craft_combined_zip()
                } else {
                    // Bug 1 (RUSTSEC-2026-0367): setuid / setgid / sticky. Default.
                    archives::craft_suid_zip()
                };
                run_through_sandbox(zip).await
            }

            // Upload path: the browser POSTs a .zip here; we read it off our own
            // request body and stream it across the link to the extractor. Even
            // an uploaded archive never lands on disk in this component.
            (Method::Post, "/run") => {
                let zip = match read_request_body(request).await {
                    Ok(b) => b,
                    Err(e) => {
                        let msg = format!("{{\"error\":\"could not read upload: {e}\"}}");
                        return respond(400, "application/json; charset=utf-8", msg.into_bytes());
                    }
                };
                run_through_sandbox(zip).await
            }

            // Still downloadable so you can inspect the raw bytes yourself.
            (Method::Get, "/suid.zip") => {
                respond_attachment("application/zip", "suid.zip", archives::craft_suid_zip())
            }
            (Method::Get, "/slip.zip") => {
                respond_attachment("application/zip", "slip.zip", archives::craft_zipslip_zip())
            }
            (Method::Get, "/cloak.zip") => {
                respond_attachment("application/zip", "cloak.zip", archives::craft_cloak_zip())
            }
            (Method::Get, "/all.zip") => {
                respond_attachment("application/zip", "all.zip", archives::craft_combined_zip())
            }
            // The branded infographic, served to the page's hero banner.
            (Method::Get, "/hero.png") => respond(200, "image/png", HERO_PNG.to_vec()),
            // The Cosmonic icon as the browser-tab favicon.
            (Method::Get, "/favicon.svg") => {
                respond(200, "image/svg+xml; charset=utf-8", FAVICON_SVG.to_vec())
            }
            _ => respond(404, "text/plain; charset=utf-8", b"not found\n".to_vec()),
        }
    }
}

/// Open a live `stream<u8>`, feed the crafted archive bytes into it from a
/// spawned task, and hand the read end to the extractor across the runtime
/// link. The extractor drains the stream, unzips in its sandbox, and returns
/// the JSON verdict — which we pass straight back to the browser.
async fn run_through_sandbox(zip: Vec<u8>) -> Result<Response, ErrorCode> {
    let (mut writer, reader) = wasip3::wit_stream::new();

    // Feed the archive into the stream concurrently; the extractor reads it off
    // the other end of the linker as we write. Dropping the writer signals EOF.
    wasip3::spawn_local(async move {
        let _unwritten = writer.write_all(zip).await;
        drop(writer);
    });

    // Cross-component call: the host routes this to the extractor's export.
    let verdict_json = extraction::extract(reader).await;
    respond(200, "application/json; charset=utf-8", verdict_json.into_bytes())
}

/// Read this component's own incoming request body (an uploaded archive) into
/// memory so it can be re-streamed across the link. The body arrives as a p3
/// stream; we collect it because we re-frame it into a fresh stream to the
/// extractor.
async fn read_request_body(request: Request) -> Result<Vec<u8>, String> {
    let body = IncomingRequestBody::new(request).map_err(|e| format!("bad body: {e}"))?;
    let collected = body.collect().await.map_err(|e| format!("read error: {e}"))?;
    Ok(collected.to_bytes().to_vec())
}

/// Tiny query matcher: true if `key=value` is present in the raw query string.
fn query_has(query: &str, key: &str, value: &str) -> bool {
    query.split('&').any(|pair| {
        let mut it = pair.splitn(2, '=');
        it.next() == Some(key) && it.next() == Some(value)
    })
}

fn respond(status: u16, content_type: &str, body: Vec<u8>) -> Result<Response, ErrorCode> {
    build_response(status, &[("content-type", content_type.as_bytes().to_vec())], body)
}

fn respond_attachment(
    content_type: &str,
    filename: &str,
    body: Vec<u8>,
) -> Result<Response, ErrorCode> {
    build_response(
        200,
        &[
            ("content-type", content_type.as_bytes().to_vec()),
            (
                "content-disposition",
                format!("attachment; filename=\"{filename}\"").into_bytes(),
            ),
        ],
        body,
    )
}

/// Shared p3 response builder: set headers + status, then stream the one body
/// frame from a spawned component-model task (the rust-http template pattern).
fn build_response(
    status: u16,
    header_pairs: &[(&str, Vec<u8>)],
    body: Vec<u8>,
) -> Result<Response, ErrorCode> {
    let list: Vec<(String, Vec<u8>)> = header_pairs
        .iter()
        .map(|(k, v)| ((*k).to_string(), v.clone()))
        .collect();
    let headers = Fields::from_list(&list)
        .map_err(|err| ErrorCode::InternalError(Some(format!("invalid headers: {err}"))))?;

    let (mut writer, body_rx, result_rx) = BodyWriter::new();
    let (response, _transmit) = Response::new(headers, Some(body_rx), result_rx);
    response
        .set_status_code(status)
        .map_err(|()| ErrorCode::InternalError(Some("invalid status code".into())))?;

    wasip3::spawn_local(async move {
        let frame = http_body::Frame::data(bytes::Bytes::from(body));
        let _ = writer.send_frame(frame).await;
        drop(writer.stream_writer);
        let _ = writer.result_writer.write(Ok(None)).await;
    });

    Ok(response)
}
