# @perplexityai/bumblebee

npm wrapper for [bumblebee](https://github.com/perplexityai/bumblebee) — a read-only supply-chain inventory collector for package, extension, and developer-tool metadata on macOS and Linux.

## Install

```sh
npm install -g @perplexityai/bumblebee
```

The postinstall script downloads the pre-built binary from GitHub Releases. If that fails, it falls back to `go install` (requires Go 1.25+).

## Usage

```sh
bumblebee scan --profile baseline > inventory.ndjson
bumblebee scan --profile deep --root "$HOME" --exposure-catalog ./catalog.json
```

See the [full documentation](https://github.com/perplexityai/bumblebee) for details.

## License

Apache-2.0
