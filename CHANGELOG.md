# Changelog

All notable changes to cvescope. Versions follow [semantic versioning](https://semver.org/);
releases are on the [releases page](https://github.com/magikh0e/cvescope/releases).

## [Unreleased]

### Added
- Optional NVD lookup (`[nvd] enabled = true`). For "check" matches the CVE List can't settle
  and that are visible in act now or watch, cvescope asks NVD for its CPE version ranges and
  re-matches with them. Off by default, works without an API key (slow: 5 requests per 30 s),
  caps lookups per run with `max_per_run`, and caches answers (empty ones are retried after
  7 days, the rest after 60).
- The CVE detail panel's history says what happened ("added to CISA KEV", "EPSS jumped
  12% -> 85%") instead of showing raw event kinds.

### Changed
- The version number lives only in `cvescope/__init__.py`; `pyproject.toml` reads it from there.

## [0.2.3] - 2026-11-16

### Added
- Each full `cvescope sync` records when it finished and which feeds and collectors failed.
  The page header shows "synced N ago", and a banner appears when the last full sync is older
  than `serve.stale_after_hours` (default 12), none was ever recorded, or something failed.
  `cvescope status` prints the same.

### Changed
- Auto-updating apps (Chrome, Edge, Firefox, Thunderbird, VS Code, Signal, Telegram,
  Bitwarden): a CVE record with no version data that's over a year old counts as not affected.
- A "check" on a distro or vendor build (backported kernels, FreeBSD base, packages no tracker
  answered) only surfaces when it's exploited (act now). A PoC or high EPSS alone no longer
  puts it in watch.

### Fixed
- dpkg: removed packages ("rc") are skipped. `dpkg-query -W` lists them next to installed
  ones; the collector now reads `${db:Status-Abbrev}`. osquery's `deb_packages` gets the same
  filter through its status column.

## [0.2.2] - 2026-11-16

### Added
- `--log FILE` appends everything a run prints to a file (rotated at 5 MB) and logs an
  exception with its traceback. For pythonw, Task Scheduler and cron runs, where there's no
  console. The README covers cron and Task Scheduler.

## [0.2.1] - 2026-11-16

### Added
- osquery live mode: without a `path`, the collector runs `osqueryi --json` itself, locally or
  over ssh (`command_prefix`), with queries picked per OS. `queries` replaces the defaults.

### Fixed
- Dropped the plain `microsoft:edge` alias. Old records with that name are EdgeHTML (retired
  2021), not Chromium Edge.

## [0.2.0] - 2026-11-16

### Added
- `distro` source: the Debian security tracker (OSV export) and Ubuntu package OVAL, fetched
  only for the releases your inventory runs. Distro packages get the tracker's fixed or
  affected answer, backports included, instead of "check". Debian "unimportant" issues count
  as not affected.
- `nmap_xml` collector: imports identified services from `nmap -sV` XML. cvescope still never
  scans anything itself.
- `docker` collector: apps in running Docker or Podman containers, locally or over ssh.
- `osquery` collector: osqueryi JSON, osqueryd logs, or `examples/windows-inventory.ps1`.
- `wpscan` and `whatweb` collectors read scanner reports.
- The `proxmox` collector lists every VM and container; guest OS and kernel come from the
  guest agent.
- The `dpkg` collector reads os-release and source packages; `packages = "all"`.
- Logo, social preview card and SVG favicon.

### Changed
- `sync` collects inventory before fetching feeds, so the distro source knows which releases
  to fetch.
- The CVE List's `packageName` is indexed (WordPress plugin slugs).

## [0.1.0] - 2026-11-16

First release.

- Full CVE List (cvelistV5) baseline plus hourly and daily deltas, with CISA Vulnrichment SSVC
  and CPEs.
- Exploitation signals: CISA KEV, EPSS, Metasploit, Nuclei, Exploit-DB, PoC-in-GitHub
  (metadata only) and local exploit archives.
- Inventory collectors: Proxmox, OPNsense, UniFi, Pi-hole, Home Assistant, static, command,
  dpkg and http_json, with certificate pinning for self-signed gear.
- Version-range matching, with fixes for common CVE record quirks.
- Act now / watch / info tiers, change events, and ntfy, Home Assistant and webhook alerts.
- A local web page (127.0.0.1, Host header checked) and a CLI.

[Unreleased]: https://github.com/magikh0e/cvescope/compare/v0.2.3...HEAD
[0.2.3]: https://github.com/magikh0e/cvescope/compare/v0.2.2...v0.2.3
[0.2.2]: https://github.com/magikh0e/cvescope/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/magikh0e/cvescope/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/magikh0e/cvescope/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/magikh0e/cvescope/releases/tag/v0.1.0
