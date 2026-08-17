import os
import stat
import tempfile
import unittest
import zipfile

from zip_inspector import inspect_zip


class ZipInspectorTests(unittest.TestCase):
    def make_zip(self, entries):
        handle = tempfile.NamedTemporaryFile(suffix=".zip", delete=False)
        handle.close()
        self.addCleanup(lambda: os.path.exists(handle.name) and os.unlink(handle.name))
        with zipfile.ZipFile(handle.name, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for name, data in entries:
                archive.writestr(name, data)
        return handle.name

    def test_returns_metadata_without_extracting(self):
        path = self.make_zip([("docs/", b""), ("docs/readme.txt", b"hello")])
        self.assertEqual(
            inspect_zip(path),
            [
                {"name": "docs/", "size": 0, "is_dir": True},
                {"name": "docs/readme.txt", "size": 5, "is_dir": False},
            ],
        )

    def test_rejects_traversal_absolute_and_platform_specific_paths(self):
        for unsafe in ("../escape", "a/../../escape", "/absolute", r"..\escape", "C:/escape"):
            with self.subTest(unsafe=unsafe):
                path = self.make_zip([(unsafe, b"x")])
                with self.assertRaises(ValueError):
                    inspect_zip(path)

    def test_rejects_embedded_nul_in_raw_member_name(self):
        path = self.make_zip([("badXname", b"x")])
        with open(path, "rb") as stream:
            contents = stream.read()
        self.assertEqual(contents.count(b"badXname"), 2)
        with open(path, "wb") as stream:
            stream.write(contents.replace(b"badXname", b"bad\x00name"))
        with self.assertRaises(ValueError):
            inspect_zip(path)

    def test_rejects_non_regular_member_types(self):
        path = self.make_zip([])
        link = zipfile.ZipInfo("link")
        link.create_system = 3
        link.external_attr = (stat.S_IFLNK | 0o777) << 16
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr(link, "../target")
        with self.assertRaises(ValueError):
            inspect_zip(path)

    def test_enforces_count_before_accepting_members(self):
        path = self.make_zip([("one", b""), ("two", b"")])
        with self.assertRaisesRegex(ValueError, "too many"):
            inspect_zip(path, max_files=1)

    def test_enforces_total_expanded_size(self):
        path = self.make_zip([("a", b"a" * 6), ("b", b"b" * 5)])
        with self.assertRaisesRegex(ValueError, "expanded-size"):
            inspect_zip(path, max_expanded_size=10)

    def test_rejects_malformed_archive_as_value_error(self):
        handle = tempfile.NamedTemporaryFile(delete=False)
        handle.write(b"not a zip")
        handle.close()
        self.addCleanup(lambda: os.path.exists(handle.name) and os.unlink(handle.name))
        with self.assertRaises(ValueError):
            inspect_zip(handle.name)

    def test_rejects_invalid_limits(self):
        path = self.make_zip([])
        for kwargs in (
            {"max_files": -1},
            {"max_files": True},
            {"max_expanded_size": -1},
            {"max_expanded_size": 1.5},
        ):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                inspect_zip(path, **kwargs)

    def test_does_not_create_archive_member_on_host(self):
        with tempfile.TemporaryDirectory() as directory:
            target = os.path.join(directory, "escaped")
            path = self.make_zip([("../escaped", b"payload")])
            with self.assertRaises(ValueError):
                inspect_zip(path)
            self.assertFalse(os.path.exists(target))


if __name__ == "__main__":
    unittest.main()
