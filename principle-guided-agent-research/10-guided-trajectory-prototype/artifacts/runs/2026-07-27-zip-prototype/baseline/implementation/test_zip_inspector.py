import stat
import tempfile
import unittest
import zipfile
from pathlib import Path

from zip_inspector import inspect_zip


class InspectZipTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.root = Path(self.temp_dir.name)

    def make_zip(self, name: str, members: dict[str, bytes]) -> Path:
        path = self.root / name
        with zipfile.ZipFile(path, "w") as archive:
            for member_name, contents in members.items():
                archive.writestr(member_name, contents)
        return path

    def test_returns_file_and_directory_metadata(self) -> None:
        path = self.make_zip(
            "normal.zip",
            {"folder/": b"", "folder/hello.txt": b"hello"},
        )

        self.assertEqual(
            inspect_zip(str(path)),
            [
                {"name": "folder/", "size": 0, "is_dir": True},
                {"name": "folder/hello.txt", "size": 5, "is_dir": False},
            ],
        )

    def test_rejects_too_many_members(self) -> None:
        path = self.make_zip("many.zip", {"one": b"", "two": b""})

        with self.assertRaisesRegex(ValueError, "too many"):
            inspect_zip(str(path), max_files=1)

    def test_rejects_excessive_total_expanded_size(self) -> None:
        path = self.make_zip("large.zip", {"one": b"123", "two": b"456"})

        with self.assertRaisesRegex(ValueError, "expanded size"):
            inspect_zip(str(path), max_expanded_size=5)

    def test_limit_is_inclusive(self) -> None:
        path = self.make_zip("boundary.zip", {"one": b"123"})

        self.assertEqual(len(inspect_zip(str(path), max_files=1, max_expanded_size=3)), 1)

    def test_rejects_posix_and_windows_path_traversal(self) -> None:
        for index, unsafe_name in enumerate(
            ("../escape", "safe/../../escape", r"..\escape")
        ):
            with self.subTest(name=unsafe_name):
                path = self.make_zip(f"traversal-{index}.zip", {unsafe_name: b"x"})
                with self.assertRaises(ValueError):
                    inspect_zip(str(path))

    def test_rejects_absolute_paths(self) -> None:
        for index, unsafe_name in enumerate(
            ("/absolute", r"\windows-rooted", r"C:\absolute")
        ):
            with self.subTest(name=unsafe_name):
                path = self.make_zip(f"absolute-{index}.zip", {unsafe_name: b"x"})
                with self.assertRaises(ValueError):
                    inspect_zip(str(path))

    def test_rejects_symbolic_links(self) -> None:
        path = self.root / "link.zip"
        link = zipfile.ZipInfo("link")
        link.create_system = 3
        link.external_attr = (stat.S_IFLNK | 0o777) << 16
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr(link, "target")

        with self.assertRaisesRegex(ValueError, "unsupported file type"):
            inspect_zip(str(path))

    def test_malformed_and_missing_archives_raise_value_error(self) -> None:
        malformed = self.root / "bad.zip"
        malformed.write_bytes(b"not a zip file")

        for path in (malformed, self.root / "missing.zip"):
            with self.subTest(path=path):
                with self.assertRaises(ValueError):
                    inspect_zip(str(path))

    def test_rejects_invalid_limits(self) -> None:
        path = self.make_zip("empty.zip", {})

        for kwargs in (
            {"max_files": -1},
            {"max_expanded_size": -1},
            {"max_files": True},
            {"max_expanded_size": 1.5},
        ):
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(ValueError):
                    inspect_zip(str(path), **kwargs)


if __name__ == "__main__":
    unittest.main()
