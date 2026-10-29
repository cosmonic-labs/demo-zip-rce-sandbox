# native-demo: watch the bugs work, with no sandbox

A small Rust CLI that runs the vulnerable `zip` 8.6.0 crate directly on your machine (macOS or Linux),
so you can see all three of the demo's bugs succeed before you watch the sandbox contain them.

- **Bug 1, setuid bits:** [RUSTSEC-2026-0367](https://rustsec.org/advisories/RUSTSEC-2026-0367.html)
  (CWE-732, CVSS 7.3). Extraction keeps the setuid, setgid and sticky bits from the archive instead of
  masking them. The crate's writer masks them with `& 0o777`; its reader doesn't.
- **Bug 3, zip cloaking:** [CVE-2026-115905](https://www.cve.org/CVERecord?id=CVE-2026-115905)
  (CWE-436 / CWE-20, CVSS 10.0). `ZipArchive` reads the central directory, which is what a scanner
  sees. A streaming extractor reads the local file header, which is what lands on disk. A crafted
  archive gives the two different names.

- **Bug 2, zip slip:** zip 8.6.0 refuses `../` names, but on a Unix target its `extract()` creates
  symlink entries without checking where they point. The archive plants links to `/etc/cron.d`,
  `/root/.ssh/authorized_keys` and `/tmp`; anything that later writes through one writes the real
  target. The CLI only plants the links and shows where they point.

> **Non-weaponized.** The crafted archives contain only inert text. The CLI sets the hostile
> permission bits and entry names and shows what survives extraction. It ships no executable and
> performs no privilege escalation.

## Run it

You need a Rust toolchain (`cargo`).

```bash
cd native-demo
cargo run              # all three bugs, in a fresh temp directory
cargo run -- slip      # bug 2 only
cargo run -- cloak     # bug 3 only
```

Bug 1's verdict:

```
    extracted installer-helper  mode=0o4755
      !! setuid (S_ISUID) PRESERVED  <-- privileged bit survived extraction
==== VERDICT ====
VULNERABLE: 1 file(s) kept a SUID/SGID/sticky bit after extraction.
```

Bug 3's verdict:

```
[scan] zip::ZipArchive (central directory) reports 1 entr(y/ies):
         central-directory name = "release-notes.txt"   <-- looks benign
[write] read_zipfile_from_stream (local headers) extracted:
         local-header name      = "config/app.conf"   <-- what actually hit disk
==== VERDICT (Bug 3) ====
VULNERABLE: the archive advertised "release-notes.txt" in its central directory, but the
streaming extractor wrote "config/app.conf". ...
```

The run prints its temp directory. Check the setuid bit with the OS:

```bash
ls -l <temp>/extracted/installer-helper    # -rwsr-xr-x  (the s is setuid)
```

## Other commands

```bash
cargo run -- craft attack.zip          # write the crafted setuid archive and stop
cargo run -- extract attack.zip out/   # extract any archive and report its permission bits
```

## Why it matters

If a privileged process (an installer, a CI/CD job, a container build running as root) extracts an
attacker's archive this way, the planted file lands root-owned with the setuid bit set. A cloaked
archive gets past a scanner and overwrites a file the service trusts.

## The two fixes

1. **Patch:** upgrade to `zip` 9.0.5, which fixes both published advisories (setuid and cloaking).
2. **Contain:** run extraction where those bits can't be applied and the writer can't leave its folder.
   That's the [sandboxed demo](../README.md): the same crate, compiled to a Cosmonic workload.
