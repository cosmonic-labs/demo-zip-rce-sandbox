//! The sandboxed extraction logic for the two zip-crate bugs:
//!   - RUSTSEC-2026-0367 (setuid/setgid/sticky preserved on extract), and
//!   - CVE-2026-115905 (zip cloaking: central-dir name hides the local-header
//!     path a streaming extractor honors).
//! The sandbox makes BOTH harmless: no Unix permission model, and a single
//! preopen that an overwrite — hidden or not — cannot escape.
//!
//! This runs the SAME vulnerable crate (`zip` 8.6.0) and calls the vulnerable
//! API itself, `ZipArchive::extract`. We do not patch the crate and we do not
//! mask the bits ourselves; the setuid bits counted as "applied" are read back
//! from disk. The point is to show that the WASM sandbox makes the vulnerable
//! behavior harmless:
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
    /// What `ZipArchive::extract` returned: None on success, else the crate's own
    /// error (it aborts on the first entry whose path escapes the root).
    pub crate_extract_error: Option<String>,
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
        crate_extract_error: None,
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

    // Pass 1: inspect every entry, writing nothing. This is what the report
    // shows: what the archive ASKED for. Cloaked entries keep their contents for
    // pass 3, which models the streaming extractor.
    let mut extracted_rel: Vec<Option<PathBuf>> = Vec::new();
    let mut cloaked: Vec<(usize, PathBuf, Vec<u8>)> = Vec::new();
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
                extracted_rel.push(None);
                continue;
            }
        };

        // `name` is the CENTRAL-directory name (what a scanner clears, and what
        // `ZipArchive::extract` writes). `honored` is the LOCAL-header name a
        // streaming extractor writes.
        let name = entry.name().to_string();
        let honored = local_names.get(i).cloned().unwrap_or_else(|| name.clone());
        let is_cloaked = honored != name;

        // The vulnerable value: unix_mode() returns external_attributes>>16 with
        // NO masking, and it is exactly what `extract()` hands to set_permissions
        // on a Unix target. Read here only to report what the archive asked for.
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

        let traversal = confine(Path::new(&honored)).is_none();
        if traversal {
            report.traversals_blocked += 1;
        }
        if is_cloaked && !traversal {
            let mut contents = Vec::new();
            if entry.read_to_end(&mut contents).is_ok() {
                cloaked.push((i, confine(Path::new(&honored)).unwrap_or_default(), contents));
            }
        }
        extracted_rel.push(if traversal || is_cloaked { None } else { confine(Path::new(&name)) });

        report.entries.push(EntryReport {
            name,
            cloaked_as: if is_cloaked { Some(honored) } else { None },
            declared_mode,
            declared_setuid: setuid,
            declared_setgid: setgid,
            declared_sticky: sticky,
            written_to: None,
            bytes_written: 0,
            traversal_blocked: traversal,
            note: String::new(),
        });
    }

    // Pass 2: the vulnerable call itself. `ZipArchive::extract` is the API
    // RUSTSEC-2026-0367 lives in: on a Unix target it copies each entry's
    // unix_mode() straight into set_permissions, setuid bit and all. Here it runs
    // unpatched; wasm32-wasip2 is not a Unix target, so that `#[cfg(unix)]` code
    // was compiled out of this component and there is no permission call to make.
    //
    // extract() canonicalizes its target first. Under WASI that resolves a path
    // by walking up from `/`, which this component cannot see (its only preopen
    // is SANDBOX_ROOT), so we step into the root and extract ".".
    let extracted = if cfg!(target_os = "wasi") {
        std::env::set_current_dir(root)
            .map_err(zip::result::ZipError::from)
            .and_then(|()| archive.extract("."))
    } else {
        archive.extract(root)
    };
    let crate_error = extracted.err().map(|e| e.to_string());
    report.crate_extract_error = crate_error.clone();

    // Measure what extract() actually left on disk, rather than assert it.
    for (i, rel) in extracted_rel.iter().enumerate() {
        let entry = &mut report.entries[i];
        if entry.traversal_blocked {
            entry.note = "path escapes the extraction root: zip's own extract() rejects it (\"Invalid file path\") and aborts, and the WASI preopen makes it unwritable anyway".into();
            continue;
        }
        let Some(rel) = rel else { continue };
        match std::fs::metadata(root.join(rel)) {
            Ok(md) => {
                report.files_extracted += 1;
                let applied = applied_privileged_bits(&root.join(rel));
                if applied != 0 {
                    report.privileged_bits_applied += 1;
                    if applied & 0o4000 != 0 {
                        report.setuid_bits_applied += 1;
                    }
                }
                entry.written_to = Some(rel.to_string_lossy().into_owned());
                entry.bytes_written = md.len();
                entry.note = if applied != 0 {
                    format!("extract() applied privileged bits {applied:#o}")
                } else if entry.declared_setuid || entry.declared_setgid || entry.declared_sticky {
                    if !cfg!(unix) {
                        "extracted by the vulnerable ZipArchive::extract, privileged bit NOT applied: wasm32-wasip2 is not a Unix target, so the crate's set_permissions code is compiled out and the WASI filesystem has no mode bits at all".to_string()
                    } else if crate_error.is_some() {
                        "extracted, privileged bit not applied: extract() sets permissions in a second pass, and it aborted before reaching it".to_string()
                    } else {
                        "extracted, privileged bit not applied: the OS dropped it (macOS clears setgid when you are not in the file's group)".to_string()
                    }
                } else {
                    "extracted by ZipArchive::extract inside the sandbox tmp dir".to_string()
                };
            }
            Err(_) => {
                entry.note = match &crate_error {
                    Some(e) => format!("not written: extract() stopped first ({e})"),
                    None => "not written".to_string(),
                };
            }
        }
    }

    // Pass 3: the cloaked entries, as a STREAMING extractor writes them: to the
    // local-header path the scanner never saw. ZipArchive::extract above trusts
    // the central directory, so this is where CVE-2026-115905 is exercised.
    for (i, rel, contents) in cloaked {
        let honored = report.entries[i].cloaked_as.clone().unwrap_or_default();
        let target = root.join(&rel);
        if let Some(parent) = target.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let entry = &mut report.entries[i];
        match std::fs::write(&target, &contents) {
            Ok(()) => {
                report.files_extracted += 1;
                let landed = rel.to_string_lossy().into_owned();
                entry.note = format!("cloaked write honored but confined: the local-header path {honored:?} landed at {}/{landed} — inside the one directory this component can write", report.sandbox_root);
                entry.written_to = Some(landed);
                entry.bytes_written = contents.len() as u64;
            }
            Err(e) => entry.note = format!("write refused by sandbox: {e}"),
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

/// The setuid/setgid/sticky bits actually set on an extracted file. On a Unix
/// target this reads the real mode. A WASI filestat carries no mode field at all
/// (type, size, timestamps, link count), so in the sandbox there is nothing that
/// could have been applied.
fn applied_privileged_bits(path: &Path) -> u32 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path).map(|m| m.permissions().mode() & 0o7000).unwrap_or(0)
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        0
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
