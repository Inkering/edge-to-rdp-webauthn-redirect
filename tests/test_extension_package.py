import json
from pathlib import Path
import shutil
import struct
import tempfile
import unittest
from unittest.mock import patch
from zipfile import ZipFile

from tools import package_extension


ROOT = Path(__file__).resolve().parent.parent


class ExtensionPackageTests(unittest.TestCase):
    def test_manifest_metadata_and_permissions(self):
        manifest = json.loads((ROOT / "extension/manifest.json").read_text())
        self.assertEqual(manifest["manifest_version"], 3)
        self.assertEqual(manifest["name"], "Linux Edge to RDP WebAuthn Redirect")
        self.assertLessEqual(len(manifest["short_name"]), 12)
        self.assertLessEqual(len(manifest["description"]), 132)
        self.assertIn("Preview", manifest["description"])
        self.assertIn("helper", manifest["description"])
        self.assertEqual(set(manifest["permissions"]),
                         {"webAuthenticationProxy", "nativeMessaging"})
        for field in ("host_permissions", "content_scripts", "key", "update_url"):
            self.assertNotIn(field, manifest)
        resources = {
            "manifest.json", manifest["background"]["service_worker"],
            *manifest["icons"].values(), *manifest["action"]["default_icon"].values(),
        }
        self.assertEqual(resources, set(package_extension.FILES))

    def test_icons_are_pngs_at_declared_sizes(self):
        manifest = json.loads((ROOT / "extension/manifest.json").read_text())
        icons = [(ROOT / "extension" / path, int(size))
                 for size, path in manifest["icons"].items()]
        icons.append((ROOT / "publishing/logo300.png", 300))
        for path, size in icons:
            with self.subTest(path=path):
                data = path.read_bytes()
                self.assertEqual(data[:8], b"\x89PNG\r\n\x1a\n")
                self.assertEqual(data[12:16], b"IHDR")
                self.assertEqual(struct.unpack(">II", data[16:24]), (size, size))

    def test_package_is_reproducible_and_excludes_nonruntime_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "extension"
            shutil.copytree(ROOT / "extension", source)
            (source / "private-session.json").write_text('{"test":"do not ship"}')
            (source / "private-key.pem").write_text("synthetic marker; not a real key")
            with patch.object(package_extension, "EXTENSION", source):
                first = package_extension.build_package(root / "first")
                second = package_extension.build_package(root / "second")
            self.assertEqual(first.read_bytes(), second.read_bytes())
            with ZipFile(first) as archive:
                self.assertEqual(set(archive.namelist()), set(package_extension.FILES))
                self.assertIsNone(archive.testzip())
                for name in package_extension.FILES:
                    self.assertEqual(archive.read(name), (source / name).read_bytes())
                version = json.loads(archive.read("manifest.json"))["version"]
                self.assertEqual(first.name, f"edge-to-rdp-webauthn-redirect-{version}.zip")


if __name__ == "__main__":
    unittest.main()
