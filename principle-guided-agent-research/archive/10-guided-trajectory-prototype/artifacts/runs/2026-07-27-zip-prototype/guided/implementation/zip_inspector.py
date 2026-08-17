"""Safe, metadata-only inspection of untrusted ZIP archives."""

from __future__ import annotations

import os
import stat
import struct
import unicodedata
import zipfile
from typing import BinaryIO


_MAX_CENTRAL_DIRECTORY_RECORD = 46 + (3 * 65_535)


def _validate_limit(name: str, value: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{name} must be a non-negative integer")


def _open_archive(path: str) -> BinaryIO:
    if not isinstance(path, str) or not path:
        raise ValueError("path must be a non-empty string")

    flags = os.O_RDONLY
    flags |= getattr(os, "O_CLOEXEC", 0)
    # Refusing a final-component symlink keeps the object being inspected
    # confined to exactly the file the caller named.
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise ValueError("archive path must name a regular file")
            return os.fdopen(fd, "rb")
        except Exception:
            os.close(fd)
            raise
    except ValueError:
        raise
    except (OSError, TypeError) as exc:
        raise ValueError("archive cannot be opened safely") from exc


def _preflight_count(stream: BinaryIO, max_files: int) -> None:
    """Read only the bounded ZIP trailer before parsing the central directory."""

    try:
        end_record = zipfile._EndRecData(stream)  # type: ignore[attr-defined]
    except (OSError, ValueError, struct.error) as exc:
        raise ValueError("malformed ZIP archive") from exc
    if end_record is None:
        raise ValueError("malformed ZIP archive")

    count = end_record[zipfile._ECD_ENTRIES_TOTAL]  # type: ignore[attr-defined]
    if count > max_files:
        raise ValueError("archive contains too many members")
    directory_size = end_record[zipfile._ECD_SIZE]  # type: ignore[attr-defined]
    # A central-directory header has three independently length-limited byte
    # strings (name, extra data, and comment).  This bound prevents a forged
    # low entry count from making ZipFile allocate an unbounded member list.
    if directory_size > count * _MAX_CENTRAL_DIRECTORY_RECORD:
        raise ValueError("central directory is inconsistent with member count")
    stream.seek(0)


def _validated_name(info: zipfile.ZipInfo) -> tuple[str, bool]:
    # orig_filename retains an embedded NUL that ZipInfo.filename truncates.
    name = info.orig_filename
    if not isinstance(name, str) or not name:
        raise ValueError("member has an empty or invalid name")
    if "\x00" in name or any(unicodedata.category(ch) == "Cc" for ch in name):
        raise ValueError("member name contains a control character")
    if "\\" in name:
        raise ValueError("member name must use ZIP '/' separators")
    if name.startswith("/") or ":" in name:
        raise ValueError("absolute, drive, and alternate-stream names are forbidden")

    is_dir = info.is_dir()
    path_part = name[:-1] if is_dir else name
    if not path_part:
        raise ValueError("archive root is not a valid member")
    components = path_part.split("/")
    if any(component in ("", ".", "..") for component in components):
        raise ValueError("member name is not a normalized relative path")

    # Whitelist only regular files and directories.  In particular, reject
    # Unix symlinks, sockets, FIFOs, and devices even though no extraction is
    # performed here.
    if info.create_system == 3:
        kind = stat.S_IFMT(info.external_attr >> 16)
        if kind not in (0, stat.S_IFREG, stat.S_IFDIR):
            raise ValueError("member type is not a regular file or directory")
        if kind == stat.S_IFDIR and not is_dir:
            raise ValueError("directory metadata and name disagree")
        if kind == stat.S_IFREG and is_dir:
            raise ValueError("file metadata and name disagree")
    elif bool(info.external_attr & 0x10) != is_dir:
        raise ValueError("directory metadata and name disagree")

    return name, is_dir


def inspect_zip(
    path: str,
    *,
    max_files: int = 100,
    max_expanded_size: int = 10_000_000,
) -> list[dict[str, object]]:
    """Return validated member metadata without extracting archive contents.

    ``ValueError`` is raised for malformed archives, unsafe member names or
    types, inconsistent metadata, or a configured resource-limit violation.
    """

    _validate_limit("max_files", max_files)
    _validate_limit("max_expanded_size", max_expanded_size)

    try:
        with _open_archive(path) as stream:
            _preflight_count(stream, max_files)
            with zipfile.ZipFile(stream, mode="r") as archive:
                members = archive.infolist()
                # Defend in depth in case a malformed trailer disagrees with
                # the central directory parsed by ZipFile.
                if len(members) > max_files:
                    raise ValueError("archive contains too many members")

                result: list[dict[str, object]] = []
                total_size = 0
                seen_names: set[str] = set()
                for info in members:
                    name, is_dir = _validated_name(info)
                    if name in seen_names:
                        raise ValueError("archive contains duplicate member names")
                    seen_names.add(name)

                    size = info.file_size
                    if not isinstance(size, int) or size < 0:
                        raise ValueError("member has an invalid expanded size")
                    if is_dir and size != 0:
                        raise ValueError("directory member has a non-zero size")
                    if size > max_expanded_size - total_size:
                        raise ValueError("archive exceeds the expanded-size limit")
                    total_size += size
                    result.append({"name": name, "size": size, "is_dir": is_dir})
                return result
    except ValueError:
        raise
    except (
        zipfile.BadZipFile,
        zipfile.LargeZipFile,
        OSError,
        EOFError,
        UnicodeError,
        struct.error,
    ) as exc:
        raise ValueError("malformed ZIP archive") from exc
