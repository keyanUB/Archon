"""Safely inspect the metadata of an untrusted ZIP archive."""

from __future__ import annotations

import ntpath
import stat
import zipfile


def _validate_limit(value: int, name: str) -> None:
    """Reject limits for which comparisons would be surprising or unsafe."""
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{name} must be a non-negative integer")


def _validate_member(info: zipfile.ZipInfo) -> None:
    """Validate a member name and type without touching its contents."""
    original_name = info.orig_filename
    if not original_name or "\x00" in original_name:
        raise ValueError("ZIP member has an empty or NUL-containing name")

    # ZIP normally uses '/', but treating '\' as a separator as well prevents
    # names that become absolute or traversing when handled on Windows.
    portable_name = original_name.replace("\\", "/")
    drive, _ = ntpath.splitdrive(portable_name)
    if drive or portable_name.startswith("/"):
        raise ValueError(f"ZIP member has an absolute path: {original_name!r}")

    components = portable_name.split("/")
    if any(component == ".." for component in components):
        raise ValueError(f"ZIP member escapes the archive root: {original_name!r}")

    # Unix creators put the file type in the upper mode bits. Links and
    # devices are unsafe archive members even though this function never
    # extracts them.
    mode = info.external_attr >> 16
    file_type = stat.S_IFMT(mode)
    if file_type not in (0, stat.S_IFREG, stat.S_IFDIR):
        raise ValueError(f"ZIP member has an unsupported file type: {original_name!r}")
    if file_type == stat.S_IFDIR and not info.is_dir():
        raise ValueError(f"ZIP directory has an invalid name: {original_name!r}")

    if info.file_size < 0:
        raise ValueError(f"ZIP member has an invalid size: {original_name!r}")


def inspect_zip(
    path: str,
    *,
    max_files: int = 100,
    max_expanded_size: int = 10_000_000,
) -> list[dict[str, object]]:
    """Return bounded, safe metadata for the members of *path*.

    No member data is opened or extracted. Both limits apply to the metadata
    declared in the ZIP central directory; directories count as members.
    Malformed/unreadable archives and contract violations are reported as
    ``ValueError``.
    """
    _validate_limit(max_files, "max_files")
    _validate_limit(max_expanded_size, "max_expanded_size")

    result: list[dict[str, object]] = []
    expanded_size = 0

    try:
        with zipfile.ZipFile(path, mode="r") as archive:
            members = archive.infolist()
            if len(members) > max_files:
                raise ValueError(
                    f"ZIP contains too many members ({len(members)} > {max_files})"
                )

            for info in members:
                _validate_member(info)
                expanded_size += info.file_size
                if expanded_size > max_expanded_size:
                    raise ValueError(
                        "ZIP expanded size exceeds "
                        f"the {max_expanded_size}-byte limit"
                    )
                result.append(
                    {
                        "name": info.orig_filename,
                        "size": info.file_size,
                        "is_dir": info.is_dir(),
                    }
                )
    except ValueError:
        raise
    except Exception as exc:
        # zipfile can surface several parsing and I/O exceptions depending on
        # exactly how an archive was damaged. Expose one stable public error.
        raise ValueError(f"invalid or unreadable ZIP archive: {exc}") from exc

    return result
