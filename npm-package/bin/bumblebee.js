#!/usr/bin/env node

const { execFileSync } = require("child_process");
const path = require("path");
const fs = require("fs");

const binDir = path.join(__dirname, "..", "binary");
const ext = process.platform === "win32" ? ".exe" : "";
const binPath = path.join(binDir, `bumblebee${ext}`);

if (!fs.existsSync(binPath)) {
  console.error(
    "bumblebee binary not found. Run `npm rebuild bumblebee-scan` or install Go 1.25+ and run:\n" +
      "  go install github.com/perplexityai/bumblebee/cmd/bumblebee@v0.1.1"
  );
  process.exit(1);
}

try {
  execFileSync(binPath, process.argv.slice(2), { stdio: "inherit" });
} catch (e) {
  process.exit(e.status || 1);
}
