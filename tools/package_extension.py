"""Build a reproducible Edge Add-ons submission ZIP with extension runtime files only."""

import argparse
import json
from pathlib import Path
import re
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo


ROOT = Path(__file__).resolve().parent.parent
EXTENSION = ROOT / "extension"
FILES = (
    "manifest.json", "worker.js",
    "icons/icon16.png", "icons/icon32.png",
    "icons/icon48.png", "icons/icon128.png",
)


def build_package(output_dir):
    manifest = json.loads((EXTENSION / "manifest.json").read_text())
    version = manifest["version"]
    if not re.fullmatch(r"\d+(?:\.\d+){0,3}", version):
        raise ValueError("Invalid extension version")
    files = [(name, (EXTENSION / name).read_bytes()) for name in sorted(FILES)]
    output_dir.mkdir(parents=True, exist_ok=True)
    output = output_dir / f"edge-to-rdp-webauthn-redirect-{version}.zip"
    with ZipFile(output, "w", compression=ZIP_DEFLATED) as archive:
        for name, data in files:
            entry = ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            entry.create_system = 3
            entry.external_attr = 0o100644 << 16
            archive.writestr(entry, data, compress_type=ZIP_DEFLATED, compresslevel=9)
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=ROOT / "build")
    args = parser.parse_args()
    print(build_package(args.output_dir))


if __name__ == "__main__":
    main()
