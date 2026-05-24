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
| [`laravel-lang-2026-05-23.json`](laravel-lang-2026-05-23.json) | Laravel Lang Composer/Packagist supply-chain compromise across `laravel-lang/lang`, `laravel-lang/http-statuses`, `laravel-lang/attributes`, and `laravel-lang/actions` | [Socket, 2026-05-23](https://socket.dev/blog/laravel-lang-compromise) |
| [`nx-console-vscode-2026-05-18.json`](nx-console-vscode-2026-05-18.json) | Nx Console VS Code extension (`nrwl.angular-console` 18.95.0) compromise published to the VS Code Marketplace on 2026-05-18 (OpenVSX unaffected; remediated in 18.100.0+) | [StepSecurity, 2026-05-18](https://www.stepsecurity.io/blog/nx-console-vs-code-extension-compromised) |
| [`antv-mini-shai-hulud.json`](antv-mini-shai-hulud.json) | AntV / Mini Shai-Hulud May 2026 npm worm wave (324 packages / 643 versions across npm and PyPI; scoped to artifacts detected on or after 2026-05-13) | [Socket, 2026-05-19](https://socket.dev/blog/antv-packages-compromised) |
| [`node-ipc-credential-stealer.json`](node-ipc-credential-stealer.json) | `node-ipc` npm 2026-05 credential-stealer compromise (7 malicious versions) | [Socket, 2026-05-14](https://socket.dev/blog/node-ipc-package-compromised) |
| [`shopsprint-decimal-typosquat.json`](shopsprint-decimal-typosquat.json) | Go `github.com/shopsprint/decimal` v1.3.3 typosquat with DNS TXT backdoor | [Socket, 2026-05-19](https://socket.dev/blog/popular-go-decimal-library-typosquat-dns-backdoor) |
| [`gemstuffer.json`](gemstuffer.json) | GemStuffer RubyGems exfiltration campaign (123 gems / 155 versions) targeting UK local government | [Socket, 2026-05-13](https://socket.dev/blog/gemstuffer) |
| [`trapdoor-crypto-stealer.json`](trapdoor-crypto-stealer.json) | TrapDoor Crypto Stealer cross-ecosystem credential/wallet stealer across npm, PyPI, and Cargo/Crates.io (28 npm/PyPI entries / 378 versions; 6 Cargo packages tracked under `_cargo_packages`) | [Socket, 2026-05-24](https://socket.dev/blog/trapdoor-crypto-stealer-npm-pypi-crates) |
