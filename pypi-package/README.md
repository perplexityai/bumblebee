# bumblebee-scan

PyPI wrapper for [bumblebee](https://github.com/perplexityai/bumblebee) — a read-only supply-chain inventory collector for package, extension, and developer-tool metadata on macOS and Linux.

This is a fork of [perplexityai/bumblebee](https://github.com/perplexityai/bumblebee) that adds npm and pip installation support.

## Install

```sh
pip install bumblebee-scan
```

Also available on npm:

```sh
npm install -g bumblebee-scan
```

On first run, the wrapper downloads the pre-built binary from GitHub Releases. If that fails, it falls back to `go install` (requires Go 1.25+).

## Usage

```sh
bumblebee scan --profile baseline > inventory.ndjson
bumblebee scan --profile deep --root "$HOME" --exposure-catalog ./catalog.json
```

See the [full documentation](https://github.com/perplexityai/bumblebee) for details.

## License

Apache-2.0
