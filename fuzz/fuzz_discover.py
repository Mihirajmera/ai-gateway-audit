"""Fuzz discovery and the checks with arbitrary file contents.

The scanner reads configuration that may come from untrusted sources. discover() must skip
malformed files rather than raise, and the checks must handle whatever discover() returns.
Any exception, hang or crash is a bug.
"""
import shutil
import sys
import tempfile
from pathlib import Path

import atheris

with atheris.instrument_imports():
    from ai_gateway_audit.checks import run_all
    from ai_gateway_audit.parsers import discover

TMP = Path(tempfile.mkdtemp())
NAMES = ['config.yaml', 'docker-compose.yml', '.env']


def TestOneInput(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)
    folder = TMP / 'gw'
    shutil.rmtree(folder, ignore_errors=True)
    folder.mkdir()
    for name in NAMES:
        (folder / name).write_bytes(fdp.ConsumeBytes(fdp.ConsumeIntInRange(0, 4096)))
    for dep in discover([folder]):
        run_all(dep)


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
