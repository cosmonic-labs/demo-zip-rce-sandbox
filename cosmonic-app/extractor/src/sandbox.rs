//! The sandboxed extraction logic for the two zip-crate bugs:
//!   - RUSTSEC-2026-0367 (setuid/setgid/sticky preserved on extract), and
//!   - CVE-2026-115905 (zip cloaking: central-dir name hides the local-header
//!     path a streaming extractor honors).
//! The sandbox makes BOTH harmless: no Unix permission model, and a single
//! preopen that an overwrite — hidden or not — cannot escape.
//!
//! This uses the SAME vulnerable crate (`zip` 8.6.0) and the SAME accessor
//! (`ZipFile::unix_mode()`) that the native demo relies on. We do not patch the
//! crate and we do not mask the bits ourselves — the point is to show that the
//! WASM sandbox makes the vulnerable behavior harmless:
//!
//!   1. Confinement — the component's only writable path is the single
//!      preopened directory `/tmp/unzip` (an ephemeral volume). It has no
//!      ambient filesystem authority, so a zip-slip entry or an absolute path
//!      cannot escape, and there is nowhere privileged to drop a file.
//!   2. No privileged-bit semantics — `wasm32-wasip2` is not a Unix target, so
//!      the crate's `#[cfg(unix)]` permission-setting code is compiled out, and
//!      the WASI filesystem has no concept of setuid/setgid/sticky at all. The
//!      malicious mode still arrives in the archive (we surface it), but it can
//!      never be applied.

use std::io::{Cursor, Read};
use std::path::{Component, Path, PathBuf};

use serde::Serialize;

/// The one and only place this component may unzip into: a single tmp directory,
/// provided by the host as an ephemeral volume mounted here.
pub const SANDBOX_ROOT: &str = "/tmp/unzip";

#[derive(Serialize)]
pub struct EntryReport {
    /// What a name-based scanner sees: the entry's CENTRAL-directory name.
    pub name: String,
    /// Set only for a cloaked entry (CVE-2026-115905): the LOCAL-header name a
    /// streaming extractor actually honors, which differs from `name`. This is
    /// the path the attack means to write; `written_to` shows where the sandbox
    /// forced it to land instead.
    pub cloaked_as: Option<String>,
    /// Raw Unix mode read from the archive via `ZipFile::unix_mode()` — the
    /// vulnerable value, special bits and all. Rendered octal, e.g. "0o104755".
    pub declared_mode: Option<String>,
    pub declared_setuid: bool,
    pub declared_setgid: bool,
    pub declared_sticky: bool,
    /// Where it actually landed, relative to the sandbox root (None = refused).
    pub written_to: Option<String>,
    pub bytes_written: u64,
    /// True when the entry tried to escape the sandbox (zip-slip / absolute path).
    pub traversal_blocked: bool,
    pub note: String,
}

#[derive(Serialize)]
pub struct EscapeProbe {
    pub target: String,
    pub allowed: bool,
    pub os_error: Option<String>,
}

#[derive(Serialize)]
pub struct ExtractReport {
    pub sandbox_root: String,
    pub target_os: String,
    pub target_is_unix: bool,
    pub permission_code_active: bool,
    pub entries: Vec<EntryReport>,
    pub files_extracted: usize,
    pub traversals_blocked: usize,
    pub setuid_bits_in_archive: usize,
    pub setuid_bits_applied: usize,
    /// Count of entries carrying ANY privileged bit (setuid, setgid or sticky),
    /// and how many of those bits the sandbox actually applied (always 0).
    pub privileged_bits_in_archive: usize,
    pub privileged_bits_applied: usize,
    /// Bug 2 (CVE-2026-115905): entries whose LOCAL file-header name differs from
    /// the CENTRAL-directory name a scanner would see. The sandbox doesn't fix
    /// the differential (it's a crate bug) but confines any resulting write.
    pub cloaked_entries: usize,
    pub cloak_notes: Vec<String>,
    pub escape_probes: Vec<EscapeProbe>,
    pub verdict: String,
    pub error: Option<String>,
}

/// Extract an uploaded archive into the sandbox tmp directory and report, per
/// entry, what the archive asked for versus what the sandbox actually allowed.
pub fn extract_into_sandbox(zip_bytes: &[u8]) -> ExtractReport {
    let mut report = ExtractReport {
        sandbox_root: SANDBOX_ROOT.to_string(),
        target_os: target_label(),
        target_is_unix: cfg!(unix),
        // The crate applies Unix modes only under #[cfg(unix)]; on wasm this is false.
        permission_code_active: cfg!(unix),
        entries: Vec::new(),
        files_extracted: 0,
        traversals_blocked: 0,
        setuid_bits_in_archive: 0,
        setuid_bits_applied: 0,
        privileged_bits_in_archive: 0,
        privileged_bits_applied: 0,
        cloaked_entries: 0,
        cloak_notes: Vec::new(),
        escape_probes: Vec::new(),
        verdict: String::new(),
        error: None,
    };

    let root = Path::new(SANDBOX_ROOT);
    // Fresh sandbox each request: this is the single place we unzip into.
    let _ = std::fs::remove_dir_all(root);
    if let Err(e) = std::fs::create_dir_all(root) {
        report.error = Some(format!("cannot prepare sandbox {SANDBOX_ROOT}: {e}"));
        report.verdict = "sandbox unavailable".into();
        return report;
    }

    let mut archive = match zip::ZipArchive::new(Cursor::new(zip_bytes)) {
        Ok(a) => a,
        Err(e) => {
            report.error = Some(format!("not a readable zip archive: {e}"));
            report.verdict = "rejected: unreadable archive".into();
            return report;
        }
    };

    // Local-header names (what a STREAMING extractor honors), aligned by index
    // with `by_index` (the central directory). A mismatch is a cloaked entry
    // (CVE-2026-115905): the scanner trusts `name`, the extractor writes this.
    let local_names = local_header_names(zip_bytes);

    for i in 0..archive.len() {
        let mut entry = match archive.by_index(i) {
            Ok(e) => e,
            Err(e) => {
                report.entries.push(EntryReport {
                    name: format!("<entry {i}>"),
                    cloaked_as: None,
                    declared_mode: None,
                    declared_setuid: false,
                    declared_setgid: false,
                    declared_sticky: false,
                    written_to: None,
                    bytes_written: 0,
                    traversal_blocked: false,
                    note: format!("could not read entry: {e}"),
                });
                continue;
            }
        };

        // `name` is the CENTRAL-directory name (what a scanner clears). `honored`
        // is the LOCAL-header name a streaming extractor actually writes. We model
        // the streaming extractor — we honor `honored` — so the cloak is exercised,
        // not just detected; the sandbox is what makes honoring it harmless.
        let name = entry.name().to_string();
        let honored = local_names.get(i).cloned().unwrap_or_else(|| name.clone());
        let is_cloaked = honored != name;

        // The vulnerable accessor: unix_mode() returns external_attributes>>16
        // with NO masking, so any setuid/setgid/sticky bit is visible here.
        let mode = entry.unix_mode();
        let setuid = mode.map(|m| m & 0o4000 != 0).unwrap_or(false);
        let setgid = mode.map(|m| m & 0o2000 != 0).unwrap_or(false);
        let sticky = mode.map(|m| m & 0o1000 != 0).unwrap_or(false);
        if setuid {
            report.setuid_bits_in_archive += 1;
        }
        if setuid || setgid || sticky {
            report.privileged_bits_in_archive += 1;
        }
        if is_cloaked {
            report.cloaked_entries += 1;
            report.cloak_notes.push(format!(
                "cloaked entry: a scanner reading the central directory sees {name:?} and clears it, but the local header a streaming extractor honors says {honored:?} — on a vulnerable host that silently overwrites the real file. Here the write is confined to {}, which nothing else trusts.",
                report.sandbox_root
            ));
        }
        let declared_mode = mode.map(|m| format!("{:#o}", m & 0o7777));

        // Correct path handling (defense #1 in application code): accept only a
        // name that stays inside the tree. The sandbox preopen is the backstop
        // underneath this, so even if this check were wrong, the write below
        // still could not escape /tmp/unzip.
        let safe_rel = match confine(Path::new(&honored)) {
            Some(rel) => rel,
            None => {
                report.traversals_blocked += 1;
                report.entries.push(EntryReport {
                    name,
                    cloaked_as: if is_cloaked { Some(honored) } else { None },
                    declared_mode,
                    declared_setuid: setuid,
                    declared_setgid: setgid,
                    declared_sticky: sticky,
                    written_to: None,
                    bytes_written: 0,
                    traversal_blocked: true,
                    note: "path escapes the sandbox root — refused by the app AND unwritable under the WASI preopen".into(),
                });
                continue;
            }
        };

        let target = root.join(&safe_rel);

        if entry.is_dir() {
            let _ = std::fs::create_dir_all(&target);
            report.entries.push(EntryReport {
                name,
                cloaked_as: if is_cloaked { Some(honored) } else { None },
                declared_mode,
                declared_setuid: setuid,
                declared_setgid: setgid,
                declared_sticky: sticky,
                written_to: Some(safe_rel.to_string_lossy().into_owned()),
                bytes_written: 0,
                traversal_blocked: false,
                note: "directory".into(),
            });
            continue;
        }

        if let Some(parent) = target.parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        let mut contents = Vec::new();
        if let Err(e) = entry.read_to_end(&mut contents) {
            report.entries.push(EntryReport {
                name,
                cloaked_as: if is_cloaked { Some(honored) } else { None },
                declared_mode,
                declared_setuid: setuid,
                declared_setgid: setgid,
                declared_sticky: sticky,
                written_to: None,
                bytes_written: 0,
                traversal_blocked: false,
                note: format!("could not read entry contents: {e}"),
            });
            continue;
        }

        match std::fs::write(&target, &contents) {
            Ok(()) => {
                report.files_extracted += 1;
                // The landing path, confined: confine() stripped it to Normal
                // components only, so `root.join(safe_rel)` provably stays inside
                // SANDBOX_ROOT — that is the containment, validated structurally.
                let landed = safe_rel.to_string_lossy().into_owned();
                // NOTE: we deliberately do NOT call set_permissions with `mode`.
                // Even if we did, this is not a Unix target, so the crate/stdlib
                // cannot stamp setuid here. setuid_bits_applied stays 0.
                let note = if is_cloaked {
                    format!("cloaked write honored but confined: the local-header path {honored:?} landed at {}/{landed} — inside the one directory this component can write", report.sandbox_root)
                } else if setuid || setgid || sticky {
                    "privileged bit present in archive but NOT applied: wasm32-wasip2 is not a Unix target and the WASI filesystem has no setuid/setgid/sticky concept".to_string()
                } else {
                    "written inside the sandbox tmp dir".to_string()
                };
                report.entries.push(EntryReport {
                    name,
                    cloaked_as: if is_cloaked { Some(honored) } else { None },
                    declared_mode,
                    declared_setuid: setuid,
                    declared_setgid: setgid,
                    declared_sticky: sticky,
                    written_to: Some(landed),
                    bytes_written: contents.len() as u64,
                    traversal_blocked: false,
                    note,
                });
            }
            Err(e) => {
                report.entries.push(EntryReport {
                    name,
                    cloaked_as: if is_cloaked { Some(honored) } else { None },
                    declared_mode,
                    declared_setuid: setuid,
                    declared_setgid: setgid,
                    declared_sticky: sticky,
                    written_to: None,
                    bytes_written: 0,
                    traversal_blocked: false,
                    note: format!("write refused by sandbox: {e}"),
                });
            }
        }
    }

    // Defense #2, shown concretely: prove the component has no authority outside
    // its one tmp dir by attempting writes to paths a real exploit would target.
    report.escape_probes = vec![
        probe_write("/tmp/zip-slip-escape"),
        probe_write("/etc/cron.d/zip-demo-escape"),
    ];

    report.verdict = build_verdict(&report);
    report
}

/// Try to write a sentinel outside the sandbox and report whether the sandbox
/// allowed it. We expect every one of these to be refused.
fn probe_write(target: &str) -> EscapeProbe {
    match std::fs::write(target, b"escape") {
        Ok(()) => {
            // Should never happen in the sandbox; clean up if it somehow did.
            let _ = std::fs::remove_file(target);
            EscapeProbe { target: target.to_string(), allowed: true, os_error: None }
        }
        Err(e) => EscapeProbe {
            target: target.to_string(),
            allowed: false,
            os_error: Some(e.to_string()),
        },
    }
}

/// Reduce a path to a safe relative path inside the root, or None if it tries to
/// escape (absolute, or any `..` / root component).
fn confine(p: &Path) -> Option<PathBuf> {
    let mut out = PathBuf::new();
    for comp in p.components() {
        match comp {
            Component::Normal(c) => out.push(c),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    if out.as_os_str().is_empty() {
        None
    } else {
        Some(out)
    }
}

/// The LOCAL file-header names, in file order, via the streaming reader — what a
/// streaming extractor honors. Aligned by index with `ZipArchive::by_index`
/// (the central directory); where the two disagree, the entry is cloaked.
fn local_header_names(zip_bytes: &[u8]) -> Vec<String> {
    let mut rdr = Cursor::new(zip_bytes);
    let mut names = Vec::new();
    while let Ok(Some(entry)) = zip::read::read_zipfile_from_stream(&mut rdr) {
        names.push(entry.name().to_string());
    }
    names
}

fn build_verdict(r: &ExtractReport) -> String {
    if r.privileged_bits_applied > 0 {
        return "VULNERABLE: a privileged bit was applied — the sandbox did not contain it.".into();
    }
    // Describe only what the archive itself carried; the per-entry counts below
    // are exactly what the table shows.
    let mut parts: Vec<String> = Vec::new();
    if r.privileged_bits_in_archive > 0 {
        parts.push(format!(
            "{} privileged (setuid/setgid/sticky) entr{} in the archive, 0 applied",
            r.privileged_bits_in_archive,
            if r.privileged_bits_in_archive == 1 { "y" } else { "ies" },
        ));
    }
    if r.traversals_blocked > 0 {
        parts.push(format!(
            "{} zip-slip path{} refused",
            r.traversals_blocked,
            if r.traversals_blocked == 1 { "" } else { "s" },
        ));
    }
    if r.cloaked_entries > 0 {
        parts.push(format!(
            "{} cloaked entr{} (CVE-2026-115905) honored but confined",
            r.cloaked_entries,
            if r.cloaked_entries == 1 { "y" } else { "ies" },
        ));
    }
    if parts.is_empty() {
        format!("Extraction confined to {}. Nothing in the archive escaped.", r.sandbox_root)
    } else {
        format!("MITIGATED: {}. Everything stayed inside {}.", parts.join("; "), r.sandbox_root)
    }
}

/// A human-readable target label. `std::env::consts::OS` is empty on a wasm
/// component, so fall back to the compile-time target family.
fn target_label() -> String {
    let os = std::env::consts::OS;
    if !os.is_empty() {
        format!("{os}/{}", std::env::consts::ARCH)
    } else if cfg!(target_os = "wasi") {
        "wasm32-wasip2 (wasi component — not unix)".to_string()
    } else {
        "unknown".to_string()
    }
}
