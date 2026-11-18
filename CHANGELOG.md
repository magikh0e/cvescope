# Changelog

All notable changes to cvescope. Versions follow [semantic versioning](https://semver.org/);
releases are on the [releases page](https://github.com/magikh0e/cvescope/releases).

## [Unreleased]

## [0.2.6] - 2026-11-17

### Added
- SBOM import: the new `sbom` collector reads CycloneDX (JSON or XML) and SPDX (JSON or
  tag-value) files from syft, trivy, cdxgen or a build. Each component becomes an item: language
  packages (PyPI, npm, Maven, Go, crates.io, RubyGems, NuGet, Packagist, Hex, Pub) are checked
  against their ecosystem's advisories on OSV.dev, Debian/Ubuntu packages against the distro
  tracker, and CPEs against the CVE List. The demo config has a sample SBOM.
- Findings without a CVE ID: Proxmox advisories that name no CVE (69 of 98 today) and GitHub/OSV
  advisories with no CVE (GHSA-, PYSEC-, GO-, RUSTSEC-, MAL- for malicious releases) are kept
  under their own ID and matched, ranked, acknowledged and alerted on like CVEs. The page links
  each to its source (GitHub advisory, Proxmox forum post, osv.dev), `#GHSA-...` links open them,
  and search finds them by ID. Proxmox advisories now keep their details text.
- Reports: `cvescope report --format html|md|csv|json` writes a full report (counts, findings
  with their reasons and fixes, hosts, changes in the last `--days`, acknowledgements, blind
  spots), for one `--host` or all of them, to stdout or `--out` (date codes allowed). The page
  has report links that follow its host and tier filters, served by `/api/report`; the HTML
  report runs no scripts and prints cleanly to PDF.
- The page header shows cvescope's version, linked to its release notes; `/api/summary` reports it too.
- On PyPI: `pip install cvescope`. A `publish` workflow builds, tests and `twine check`s each GitHub release and
  uploads it with PyPI Trusted Publishing (no stored token), refusing a tag that doesn't match
  the version. README images and links are absolute, so the PyPI page shows them.

### Changed
- The `osv` source asks OSV.dev about every package in one batch query and downloads only new or
  changed advisories, so an SBOM with hundreds of packages costs a few requests per sync.

### Fixed
- An OSV advisory with one affected range per release line (Log4Shell lists 2.0-beta9..2.3.1,
  2.4..2.12.2 and 2.13.0..2.15.0) kept only the last range, so a version on another line read as
  not affected. All ranges count now, and the reason names the fix for the installed version's
  line.

## [0.2.5] - 2026-11-17

### Fixed
- A write the page refused (from another site, not JSON, too large, or `serve.read_only`)
  could reset the connection instead of answering 403/413/415, mostly on Windows: the server
  replied without reading the request body. It reads the body first now (a body over the limit
  is read and dropped, up to 1 MB), and drops a client that announces a body and never sends
  it after 30 seconds.

## [0.2.4] - 2026-11-17

### Added
- Proxmox VE hosts are checked against Proxmox's own security advisories (PSAs), read from its
  forum thread (the whole thread once, then its last page). Every CVE a PSA names is affected
  when the host's build is older than the fix for its release line, not_affected otherwise;
  kernels compare against the running kernel and say "reboot to run it" when the fixed one is
  already installed. The `proxmox` collector now always reads the host's package builds and
  running kernel (PVEAuditor is enough). New source `proxmox`.
- OPNsense and FreeBSD packages are checked against FreeBSD's VuXML (the database `pkg audit`
  reads), compared with pkg's own version rules. A CVE VuXML lists for a package build is
  affected or not_affected by its range ("fixed in 3.5.10, installed 3.5.9"); the base system is
  checked against its patch level, so old FreeBSD advisories for other releases stop showing as
  check. OPNsense's OpenSSL is tied to its `openssl35` package. New source `freebsd` (~1.4 MB,
  only fetched when the inventory has OPNsense or FreeBSD), and `packages = "all"` on the
  `opnsense` collector for every installed package.
- Home Assistant Core is checked against Home Assistant's own security advisories (OSV.dev,
  PyPI `homeassistant`), which list every affected release. The reason names the advisory and
  the fixed release, and says when Home Assistant offers an update. New source `osv`.
- The `homeassistant` collector reads Home Assistant's update entities, so Home Assistant OS,
  the Supervisor, add-ons and ESPHome device firmware show up with any long-lived token. Before,
  OS and add-ons needed an admin token.
- Optional NVD lookup (`[nvd] enabled = true`). For "check" matches the CVE List can't settle
  and that are visible in act now or watch, cvescope asks NVD for its CPE version ranges and
  re-matches with them. Off by default, works without an API key (slow: 5 requests per 30 s),
  caps lookups per run with `max_per_run`, and caches answers (empty ones are retried after
  7 days, the rest after 60).
- Acknowledgements: `cvescope ack` / `unack` / `acks`, and an Acknowledge button in the CVE
  panel. An acknowledged match leaves act now, watch, the counts and alerts, and comes back by
  itself when an optional end date passes or the evidence gets worse (a higher tier, a new kind
  of exploitation evidence, or a check that turns out affected). `report --acked` and the
  page's "show acknowledged" list the hidden ones. The page's only writes: JSON only, refused
  when another site started the request, off with `serve.read_only = true`.
- Acknowledge many at once: tick matches on the page (or "select all shown" after filtering by
  host or text), give one note and end date, and acknowledge or remove them together, with an
  undo. `cvescope ack` and `unack` take several CVE IDs. New endpoints `/api/ack/bulk` and
  `/api/unack/bulk` (same-origin and JSON only like the others, all or nothing, up to 2000).
- The page's inventory can be filtered (name, host, version), grouped by host or by source,
  and sorted by exposure or name. Clicking a host shows only its matches. The match list has
  a host picker, a text filter (CVE ID, title, item) and sorting by tier, newest, CVSS or EPSS.
  Each match says which host it's on; the choices are remembered per browser.
- One machine seen by two collectors is one host on the page: a Proxmox guest named like
  another collector's host ("VM 102 OpnSense" and OPNsense) merges automatically, and a new
  `[hosts]` config section files any other host or guest id under the name you give
  (`"VM 103" = "Home Assistant"`).
- The CVE detail panel's history says what happened ("added to CISA KEV", "EPSS jumped
  12% -> 85%") instead of showing raw event kinds.

### Changed
- Debian packages are checked against the security tracker's own JSON instead of its OSV
  export. The OSV copy turned the tracker's "not-affected" (vulnerable code never shipped in
  that release) into "no fix yet", and lagged behind it, so some Debian matches showed as
  affected with no update available. The download is also smaller (~15 MB instead of ~80 MB).
- An affected Debian match with no fix says why when the tracker does: no security update
  planned (minor issue), postponed, or queued for the next point release. Debian's
  "undetermined" now reads as check instead of affected.
- A version field that names another distro's releases ("Fedora version prior to 31", "all
  RHEL versions") no longer counts as an affected range for your product.
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

[Unreleased]: https://github.com/magikh0e/cvescope/compare/v0.2.6...HEAD
[0.2.6]: https://github.com/magikh0e/cvescope/compare/v0.2.5...v0.2.6
[0.2.5]: https://github.com/magikh0e/cvescope/compare/v0.2.4...v0.2.5
[0.2.4]: https://github.com/magikh0e/cvescope/compare/v0.2.3...v0.2.4
[0.2.3]: https://github.com/magikh0e/cvescope/compare/v0.2.2...v0.2.3
[0.2.2]: https://github.com/magikh0e/cvescope/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/magikh0e/cvescope/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/magikh0e/cvescope/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/magikh0e/cvescope/releases/tag/v0.1.0
