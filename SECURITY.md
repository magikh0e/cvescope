# Security

cvescope handles API tokens for your network gear and serves a page that lists what's
vulnerable on it, so bugs in cvescope itself matter.

## Reporting a vulnerability

Please report it privately through GitHub: **Security → Report a vulnerability** on this
repository. Don't open a public issue for it.

Useful things to include: the version (`cvescope --version`), your OS and Python version, what
an attacker needs (network position, a malicious feed, a crafted CVE record, ...), and steps to
reproduce.

I'll acknowledge reports within a week and keep you posted while a fix is in progress.

## In scope

- Leaking credentials (tokens, passwords, API keys) to the console, logs, the page, or a
  third party
- Getting the local page to serve or reveal data to another origin (DNS rebinding, CORS,
  XSS from feed content)
- Code execution or file writes driven by feed content (CVE records, PoC metadata, Exploit-DB
  or Nuclei indexes)
- Bypassing certificate pinning for collectors

## Out of scope

- Vulnerabilities in the products cvescope reports on. Report those to their vendors.
- The accuracy of upstream data (CVE records, KEV, EPSS). Wrong matches are regular bugs:
  open an issue.
- Exposing `cvescope serve` beyond localhost without authentication in front of it.
