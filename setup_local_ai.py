"""Download the local IBM Granite 2B assistant runtime (Windows x64, CPU).

    python setup_local_ai.py

This fetches llama.cpp's portable CPU server and IBM's Q3_K_M Granite 2B
instruction model into ``local_ai/`` (ignored by git). It is a ~1.3 GB one-time
download. No account or API key is needed.
"""
from __future__ import annotations

import platform
import sys
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
LOCAL = ROOT / "local_ai"
RUNTIME_ZIP = LOCAL / "runtime" / "llama.zip"
RUNTIME_URL = (
    "https://github.com/ggml-org/llama.cpp/releases/download/"
    "b12208/llama-b12208-bin-win-cpu-x64.zip"
)
MODEL = LOCAL / "models" / "granite-3.3-2b-instruct-Q3_K_M.gguf"
MODEL_URL = (
    "https://huggingface.co/ibm-granite/granite-3.3-2b-instruct-GGUF/"
    "resolve/main/granite-3.3-2b-instruct-Q3_K_M.gguf"
)


def download(url: str, destination: Path, minimum_bytes: int) -> None:
    if destination.exists() and destination.stat().st_size >= minimum_bytes:
        print(f"[local-ai] already present: {destination.name}")
        return

    destination.parent.mkdir(parents=True, exist_ok=True)
    partial = destination.with_suffix(destination.suffix + ".part")
    print(f"[local-ai] downloading {destination.name} ...")
    with urllib.request.urlopen(url, timeout=120) as response, partial.open("wb") as output:
        total = int(response.headers.get("Content-Length") or 0)
        done = 0
        while True:
            chunk = response.read(1024 * 1024)
            if not chunk:
                break
            output.write(chunk)
            done += len(chunk)
            if total:
                print(f"\r[local-ai] {done / 1e6:7.1f} / {total / 1e6:.1f} MB", end="", flush=True)
    print()
    if partial.stat().st_size < minimum_bytes:
        raise RuntimeError(f"download incomplete: {partial}")
    partial.replace(destination)


def main() -> int:
    if platform.system() != "Windows" or platform.machine().lower() not in {"amd64", "x86_64"}:
        print("[local-ai] this setup script currently targets Windows x64.", file=sys.stderr)
        return 1

    download(RUNTIME_URL, RUNTIME_ZIP, 20_000_000)
    runtime_dir = LOCAL / "runtime"
    server = runtime_dir / "llama-server.exe"
    if not server.exists():
        with zipfile.ZipFile(RUNTIME_ZIP) as archive:
            archive.extractall(runtime_dir)
        if not server.exists():
            raise RuntimeError("llama-server.exe was not found in the runtime archive")
    else:
        print("[local-ai] runtime already extracted")

    download(MODEL_URL, MODEL, 1_000_000_000)
    print(f"[local-ai] ready: {server}")
    print(f"[local-ai] ready: {MODEL}")
    print("[local-ai] start with: bash start.sh")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
