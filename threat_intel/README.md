# Threat Intelligence Exposure Catalogs

Maintained exposure catalogs for recent supply-chain campaigns, built from
public threat-intelligence reporting with
[Perplexity Computer](https://www.perplexity.ai/computer) and updated via
PRs as fresh campaigns are reported.

Pass a catalog to a scan with `--exposure-catalog <path>`. Review
the entries against current advisories before production use.

## Catalog entry fields

The bumblebee exposure loader (`internal/exposure/exposure.go`) parses
only the following fields on each entry; everything else is silently
dropped and exists purely as documentation for human reviewers.

| Field | Required? | Purpose |
|---|---|---|
| `id` | yes | Stable identifier echoed onto findings as `catalog_id` |
| `ecosystem` | yes | Matched exactly against the scanner's emitted `ecosystem` (`npm`, `pypi`, `go`, `rubygems`, `packagist`, `conda`, `mcp`, `editor-extension`, `browser-extension`) |
| `package` | yes | Matched against the normalized package name; per-ecosystem normalization (PEP 503 for `pypi`, lowercase for others) is applied on both sides |
| `versions` | yes | Non-empty list of exact version strings. Matched literally against the scanner's emitted `version` |
| `name` | no | Human label echoed onto findings as `catalog_name` |
| `severity` | no | Free-form label (`critical`, `high`, `medium`, `low`, `info`) echoed onto findings |

Fields commonly seen on existing entries but NOT interpreted by the
loader: `source`, `cve`, `ghsa`, `cvss`, `published`, `patched_version`,
`indicators`, `_comment`. Use them for human-readable provenance, IOCs
that bumblebee won't match against (network/file hashes), and notes for
future maintainers. Bare-string array members like `_cargo_packages`
(see `trapdoor-crypto-stealer.json`) are also free-form documentation.

Catalog files must be a JSON object with both `schema_version` and
`entries` keys. Bare top-level arrays are rejected. Multiple catalogs
can be loaded together by pointing `--exposure-catalog` at a directory.

## Catalogs

| File | Campaign | Source |
|---|---|---|
| [`mini-shai-hulud.json`](mini-shai-hulud.json) | Mini/Shai-Hulud May 2026 npm and PyPI compromise (OX Security affected-package table) | Cross-checked against Fleet, Socket, Snyk, Mistral, TanStack, The Hacker News |
| [`laravel-lang-2026-05-23.json`](laravel-lang-2026-05-23.json) | Laravel Lang Composer/Packagist supply-chain compromise across `laravel-lang/lang`, `laravel-lang/http-statuses`, `laravel-lang/attributes`, and `laravel-lang/actions` | [Socket, 2026-05-23](https://socket.dev/blog/laravel-lang-compromise) |
| [`nx-console-vscode-2026-05-18.json`](nx-console-vscode-2026-05-18.json) | Nx Console VS Code extension (`nrwl.angular-console` 18.95.0) compromise published to the VS Code Marketplace on 2026-05-18 (OpenVSX unaffected; remediated in 18.100.0+) | [StepSecurity, 2026-05-18](https://www.stepsecurity.io/blog/nx-console-vs-code-extension-compromised) |
| [`antv-mini-shai-hulud.json`](antv-mini-shai-hulud.json) | AntV / Mini Shai-Hulud May 2026 npm worm wave (324 packages / 643 versions across npm and PyPI; scoped to artifacts detected on or after 2026-05-13) | [Socket, 2026-05-19](https://socket.dev/blog/antv-packages-compromised) |
| [`node-ipc-credential-stealer.json`](node-ipc-credential-stealer.json) | `node-ipc` npm 2026-05 credential-stealer compromise (7 malicious versions) | [Socket, 2026-05-14](https://socket.dev/blog/node-ipc-package-compromised) |
| [`shopsprint-decimal-typosquat.json`](shopsprint-decimal-typosquat.json) | Go `github.com/shopsprint/decimal` v1.3.3 typosquat with DNS TXT backdoor | [Socket, 2026-05-19](https://socket.dev/blog/popular-go-decimal-library-typosquat-dns-backdoor) |
| [`gemstuffer.json`](gemstuffer.json) | GemStuffer RubyGems exfiltration campaign (123 gems / 155 versions) targeting UK local government | [Socket, 2026-05-13](https://socket.dev/blog/gemstuffer) |
| [`trapdoor-crypto-stealer.json`](trapdoor-crypto-stealer.json) | TrapDoor Crypto Stealer cross-ecosystem credential/wallet stealer across npm, PyPI, and Cargo/Crates.io (28 npm/PyPI entries / 378 versions; 6 Cargo packages documented under `_cargo_packages`, not matched until Cargo support lands) | [Socket, 2026-05-24](https://socket.dev/blog/trapdoor-crypto-stealer-npm-pypi-crates) |
| [`conda-forge-metadata-2025-03-04.json`](conda-forge-metadata-2025-03-04.json) | `conda-forge-metadata` PyPI package <=0.4.1 dependency-confusion RCE via the unregistered `conda-oci-mirror` optional dep (`[oci]` extras). Fixed upstream by claiming the PyPI placeholder name; affected installed releases are 0.3.0 and 0.4.1 | [GHSA-vwfh-m3q7-9jpw, 2025-03-04](https://github.com/conda-forge/conda-forge-metadata/security/advisories/GHSA-vwfh-m3q7-9jpw) |
| [`conda-tooling-2025-06-14.json`](conda-tooling-2025-06-14.json) | Three CVEs against conda-channel-distributed conda tooling disclosed by the 7ASecurity OSTIF/STA audit: `conda-build` <=25.3.2 recipe-selector RCE (CVE-2025-32798) and Tarslip path traversal (CVE-2025-32799), plus `conda-smithy` <=3.47.0 RSA padding-oracle in `travis_encrypt_binstar_token` (CVE-2025-49824). `ecosystem: "conda"` — matched by the conda-meta scanner. | [conda-forge audit summary, 2025-07-16](https://conda-forge.org/blog/2025/07/16/security-audit/) |
