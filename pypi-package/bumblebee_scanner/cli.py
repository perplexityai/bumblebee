"""CLI wrapper that finds and executes the bumblebee Go binary."""

import os
import platform
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
from pathlib import Path

VERSION = "0.1.1"
REPO = "perplexityai/bumblebee"

PLATFORM_MAP = {"Darwin": "darwin", "Linux": "linux"}
ARCH_MAP = {"x86_64": "amd64", "AMD64": "amd64", "aarch64": "arm64", "arm64": "arm64"}


def _bin_dir() -> Path:
    return Path(__file__).parent / "bin"


def _bin_path() -> Path:
    return _bin_dir() / "bumblebee"


def _download_binary() -> bool:
    plat = PLATFORM_MAP.get(platform.system())
    arch = ARCH_MAP.get(platform.machine())
    if not plat or not arch:
        return False

    tarball = f"bumblebee_{VERSION}_{plat}_{arch}.tar.gz"
    url = f"https://github.com/{REPO}/releases/download/v{VERSION}/{tarball}"

    try:
        bin_dir = _bin_dir()
        bin_dir.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(suffix=".tar.gz", delete=False) as tmp:
            urllib.request.urlretrieve(url, tmp.name)
            with tarfile.open(tmp.name, "r:gz") as tf:
                member = tf.getmember("bumblebee")
                member.name = "bumblebee"
                tf.extract(member, path=str(bin_dir))
        os.chmod(str(_bin_path()), 0o755)
        os.unlink(tmp.name)
        return True
    except Exception:
        return False


def _go_install() -> bool:
    go = shutil.which("go")
    if not go:
        return False
    bin_dir = _bin_dir()
    bin_dir.mkdir(parents=True, exist_ok=True)
    try:
        subprocess.run(
            [go, "install", f"github.com/{REPO}/cmd/bumblebee@v{VERSION}"],
            check=True,
            env={**os.environ, "GOBIN": str(bin_dir)},
        )
        return True
    except subprocess.CalledProcessError:
        return False


def _ensure_binary() -> str:
    bp = _bin_path()
    if bp.exists():
        return str(bp)

    # Also check PATH
    found = shutil.which("bumblebee")
    if found:
        return found

    print("bumblebee binary not found. Attempting download...", file=sys.stderr)
    if _download_binary():
        return str(bp)

    print("Download failed. Trying go install...", file=sys.stderr)
    if _go_install():
        return str(bp)

    print(
        f"Could not install bumblebee automatically.\n"
        f"Install Go 1.25+ and run:\n"
        f"  go install github.com/{REPO}/cmd/bumblebee@v{VERSION}",
        file=sys.stderr,
    )
    sys.exit(1)


def main() -> None:
    binary = _ensure_binary()
    result = subprocess.run([binary] + sys.argv[1:])
    sys.exit(result.returncode)


if __name__ == "__main__":
    main()
