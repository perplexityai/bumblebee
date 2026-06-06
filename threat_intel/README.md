# Threat Intelligence Exposure Catalogs

Maintained exposure catalogs for recent supply-chain campaigns, built from
public threat-intelligence reporting with
[Perplexity Computer](https://www.perplexity.ai/computer) and updated via
PRs as fresh campaigns are reported.

Pass a catalog to a scan with `--exposure-catalog <path>`. Review
the entries against current advisories before production use.

## Catalogs

| File | Campaign | Source |
|---|---|---|
| [`mini-shai-hulud.json`](mini-shai-hulud.json) | Mini/Shai-Hulud May 2026 npm and PyPI compromise (OX Security affected-package table) | Cross-checked against Fleet, Socket, Snyk, Mistral, TanStack, The Hacker News |
| [`mini-shai-hulud-redhat-cloud-services.json`](mini-shai-hulud-redhat-cloud-services.json) | Mini Shai-Hulud compromise of Red Hat Cloud Services (`@redhat-cloud-services`) npm packages (32 packages / 95 versions; "Miasma: The Spreading Blight" worm marker) | [Socket, 2026-06-01](https://socket.dev/blog/mini-shai-hulud-campaign-hits-red-hat-cloud-services-npm-packages) |
| [`laravel-lang-2026-05-23.json`](laravel-lang-2026-05-23.json) | Laravel Lang Composer/Packagist supply-chain compromise across `laravel-lang/lang`, `laravel-lang/http-statuses`, `laravel-lang/attributes`, and `laravel-lang/actions` | [Socket, 2026-05-23](https://socket.dev/blog/laravel-lang-compromise) |
| [`nx-console-vscode-2026-05-18.json`](nx-console-vscode-2026-05-18.json) | Nx Console VS Code extension (`nrwl.angular-console` 18.95.0) compromise published to the VS Code Marketplace on 2026-05-18 (OpenVSX unaffected; remediated in 18.100.0+) | [StepSecurity, 2026-05-18](https://www.stepsecurity.io/blog/nx-console-vs-code-extension-compromised) |
| [`antv-mini-shai-hulud.json`](antv-mini-shai-hulud.json) | AntV / Mini Shai-Hulud May 2026 npm worm wave (324 packages / 643 versions across npm and PyPI; scoped to artifacts detected on or after 2026-05-13) | [Socket, 2026-05-19](https://socket.dev/blog/antv-packages-compromised) |
| [`node-ipc-credential-stealer.json`](node-ipc-credential-stealer.json) | `node-ipc` npm 2026-05 credential-stealer compromise (7 malicious versions) | [Socket, 2026-05-14](https://socket.dev/blog/node-ipc-package-compromised) |
| [`shopsprint-decimal-typosquat.json`](shopsprint-decimal-typosquat.json) | Go `github.com/shopsprint/decimal` v1.3.3 typosquat with DNS TXT backdoor | [Socket, 2026-05-19](https://socket.dev/blog/popular-go-decimal-library-typosquat-dns-backdoor) |
| [`gemstuffer.json`](gemstuffer.json) | GemStuffer RubyGems exfiltration campaign (123 gems / 155 versions) targeting UK local government | [Socket, 2026-05-13](https://socket.dev/blog/gemstuffer) |
| [`glassworm.json`](glassworm.json) | GlassWorm self-propagating IDE-extension worm on Open VSX / VS Code (invisible-Unicode loader, transitive extensionPack/Dependencies delivery, Solana memo C2, credential/wallet theft); 243 `editor-extension` packages / 381 versions + 2 npm packages / 2 versions (245 entries / 383 versions) | [Socket GlassWorm v2 campaign CSV](https://socket.dev/supply-chain-attacks/glassworm-v2) and [Socket transitive report, 2026-03-13](https://socket.dev/blog/open-vsx-transitive-glassworm-campaign); supplemented by [Koi Security, 2025-10-18](https://www.koi.ai/blog/glassworm-first-self-propagating-worm-using-invisible-code-hits-openvsx-marketplace), [Checkmarx, 2026-03](https://checkmarx.com/zero-post/glassworm-targets-developer-ides-again-hiding-staged-malware-behind-runtime-rebuilt-loaders/), and [Sonatype, 2026-03-17](https://www.sonatype.com/blog/hijacked-npm-packages-deliver-malware-via-solana-linked-to-glassworm) |
| [`trapdoor-crypto-stealer.json`](trapdoor-crypto-stealer.json) | TrapDoor Crypto Stealer cross-ecosystem credential/wallet stealer across npm, PyPI, and Cargo/Crates.io (28 npm/PyPI entries / 378 versions; 6 Cargo packages documented under `_cargo_packages`, not matched until Cargo support lands) | [Socket, 2026-05-24](https://socket.dev/blog/trapdoor-crypto-stealer-npm-pypi-crates) |

## Generating catalogs from OSV

`tools/osvcatalog` converts a local [OSV](https://osv.dev) snapshot into
a catalog offline. Bumblebee never queries osv.dev at scan time. Only
malicious-package records (`MAL-` ids, or records aliased to one) are
emitted, with `severity: "critical"`.

Two input shapes are supported. Pick one based on coverage.

**OSSF malicious-packages repo** (recommended, all ecosystems in one
tree):

```sh
git clone --filter=blob:none --sparse --depth=1 \
  https://github.com/ossf/malicious-packages.git mp
git -C mp sparse-checkout set osv/malicious
go run ./tools/osvcatalog \
  -source "https://github.com/ossf/malicious-packages@$(git -C mp rev-parse HEAD)" \
  -o threat_intel/osv-malicious.json mp/osv/malicious/
```

**OSV per-ecosystem dump** (single ecosystem, zip archive):

```sh
curl -fsSLO https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip
go run ./tools/osvcatalog -o threat_intel/osv-npm-malicious.json npm/all.zip
```

Each input path can be a directory tree, an OSV `all.zip` archive, or a
single `.json` record. Supported OSV ecosystems map to Bumblebee as:
`npm`, `PyPI` → `pypi`, `Go` → `go`, `RubyGems` → `rubygems`,
`Packagist` → `packagist`, `VSCode` → `editor-extension`. Records with
only a version range and no enumerated `affected[].versions` are skipped
(v0.1 matches exact versions only); this drops the large majority of
upstream entries (~90% of the current OSSF corpus). Output is
deterministic, validates against the schema, and should be reviewed
before use. The generated `_comment` records scope, per-ecosystem
counts, skip-reason breakdown, and the optional `-source` provenance
label.
