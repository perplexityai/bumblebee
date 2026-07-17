#!/usr/bin/env node

const https = require("https");
const fs = require("fs");
const path = require("path");
const { execSync } = require("child_process");
const zlib = require("zlib");

const VERSION = "0.1.6";
// Prebuilt release binaries are published to this fork's GitHub releases.
const REPO = "anonymousAAK/bumblebee";
// Canonical Go module path, used only by the `go install` source-build
// fallback. It stays on the upstream module so the path is import-valid.
const MODULE = "github.com/perplexityai/bumblebee";

const PLATFORM_MAP = {
  darwin: "darwin",
  linux: "linux",
};

const ARCH_MAP = {
  x64: "amd64",
  arm64: "arm64",
};

const platform = PLATFORM_MAP[process.platform];
const arch = ARCH_MAP[process.arch];

if (!platform || !arch) {
  console.warn(
    `bumblebee-scan: unsupported platform ${process.platform}/${process.arch}. ` +
      `Install manually: go install ${MODULE}/cmd/bumblebee@v${VERSION}`
  );
  process.exit(0);
}

const binDir = path.join(__dirname, "..", "binary");
const binPath = path.join(binDir, "bumblebee");

fs.mkdirSync(binDir, { recursive: true });

const tarballName = `bumblebee_${VERSION}_${platform}_${arch}.tar.gz`;
const url = `https://github.com/${REPO}/releases/download/v${VERSION}/${tarballName}`;

function downloadFromRelease() {
  return new Promise((resolve, reject) => {
    const get = (u, redirects = 0) => {
      if (redirects > 5) return reject(new Error("Too many redirects"));
      const req = https.get(
        u,
        { headers: { "User-Agent": "bumblebee-npm" }, timeout: 30000 },
        (res) => {
          if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
            res.resume();
            return get(res.headers.location, redirects + 1);
          }
          if (res.statusCode !== 200) {
            res.resume();
            return reject(new Error(`HTTP ${res.statusCode} from ${u}`));
          }
          resolve(res);
        }
      );
      req.on("timeout", () => req.destroy(new Error("request timed out")));
      req.on("error", reject);
    };
    get(url);
  });
}

async function installFromRelease() {
  const res = await downloadFromRelease();
  // pipe through tar to extract the bumblebee binary
  const tar = require("child_process").spawn("tar", ["xzf", "-", "-C", binDir, "bumblebee"], {
    stdio: ["pipe", "inherit", "inherit"],
  });
  res.pipe(tar.stdin);
  return new Promise((resolve, reject) => {
    tar.on("close", (code) => {
      if (code === 0) {
        fs.chmodSync(binPath, 0o755);
        resolve();
      } else {
        reject(new Error(`tar exited with ${code}`));
      }
    });
  });
}

function installFromGo() {
  console.log("bumblebee-scan: GitHub release not available, trying go install...");
  try {
    const gobin = path.join(binDir);
    execSync(`go install ${MODULE}/cmd/bumblebee@v${VERSION}`, {
      stdio: "inherit",
      timeout: 300000,
      env: { ...process.env, GOBIN: gobin },
    });
    fs.chmodSync(binPath, 0o755);
    return true;
  } catch {
    return false;
  }
}

(async () => {
  try {
    await installFromRelease();
    console.log(`bumblebee-scan: installed v${VERSION} (${platform}/${arch})`);
  } catch (e) {
    console.warn(`bumblebee-scan: release download failed (${e.message})`);
    if (!installFromGo()) {
      console.warn(
        `bumblebee-scan: could not install binary automatically.\n` +
          `Install Go 1.25+ and run: go install ${MODULE}/cmd/bumblebee@v${VERSION}\n` +
          `Then place the binary in: ${binDir}/`
      );
    }
  }
})();
