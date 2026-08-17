"""Deterministic workspace policy for the PGACS OpenHands adapter."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path


MAX_READ_BYTES = 256_000
MAX_LIST_ENTRIES = 400
MAX_SEARCH_MATCHES = 100


class WorkspacePolicyError(ValueError):
    """Raised when an agent operation violates the admitted workspace policy."""


@dataclass(frozen=True)
class WorkspaceOperationResult:
    text: str
    path: str
    changed: bool = False


class PgacsWorkspacePolicy:
    """Repository-only reads and target-only writes with no process execution."""

    def __init__(self, workspace_root: str, target_path: str) -> None:
        self.root = Path(workspace_root).resolve(strict=True)
        if not self.root.is_dir():
            raise WorkspacePolicyError("workspace_root must be a directory")
        self.target_path = self._normalize_relative(target_path)
        target_lexical = self.root / self.target_path
        if target_lexical.is_symlink():
            raise WorkspacePolicyError("target_path must not be a symlink")
        self.target = self._resolve_existing(self.target_path)
        if not self.target.is_file():
            raise WorkspacePolicyError("target_path must be a regular non-symlink file")

    @staticmethod
    def _normalize_relative(value: str) -> str:
        candidate = Path(value)
        if candidate.is_absolute() or value == "":
            raise WorkspacePolicyError("path must be repository-relative")
        parts = candidate.parts
        if any(part in ("", ".", "..") for part in parts):
            raise WorkspacePolicyError("path contains an invalid segment")
        return candidate.as_posix()

    def _resolve_existing(self, value: str) -> Path:
        relative = self._normalize_relative(value)
        candidate = (self.root / relative).resolve(strict=True)
        try:
            candidate.relative_to(self.root)
        except ValueError as error:
            raise WorkspacePolicyError("path escapes the repository") from error
        if ".git" in Path(relative).parts:
            raise WorkspacePolicyError("git metadata is outside the admitted read surface")
        return candidate

    def _read_text(self, path: Path) -> str:
        if not path.is_file():
            raise WorkspacePolicyError("path is not a regular file")
        if path.stat().st_size > MAX_READ_BYTES:
            raise WorkspacePolicyError(f"file exceeds the {MAX_READ_BYTES}-byte read limit")
        try:
            return path.read_text(encoding="utf-8")
        except UnicodeDecodeError as error:
            raise WorkspacePolicyError("binary files are not admitted") from error

    def read(self, value: str, start_line: int = 1, end_line: int | None = None) -> WorkspaceOperationResult:
        path = self._resolve_existing(value)
        text = self._read_text(path)
        lines = text.splitlines()
        if start_line < 1:
            raise WorkspacePolicyError("start_line must be positive")
        if end_line is not None and end_line < start_line:
            raise WorkspacePolicyError("end_line must not precede start_line")
        selected = lines[start_line - 1 : end_line]
        numbered = "\n".join(
            f"{number}: {line}" for number, line in enumerate(selected, start=start_line)
        )
        return WorkspaceOperationResult(numbered, self.relative(path))

    def list_files(self, value: str = "") -> WorkspaceOperationResult:
        if value:
            directory = self._resolve_existing(value)
        else:
            directory = self.root
        if not directory.is_dir():
            raise WorkspacePolicyError("list path is not a directory")
        entries: list[str] = []
        for candidate in sorted(directory.rglob("*")):
            relative = self.relative(candidate)
            if ".git" in Path(relative).parts or candidate.is_symlink():
                continue
            if candidate.is_file():
                entries.append(relative)
            if len(entries) >= MAX_LIST_ENTRIES:
                break
        return WorkspaceOperationResult("\n".join(entries), self.relative(directory))

    def search(self, query: str, value: str = "") -> WorkspaceOperationResult:
        if not query or len(query) > 500:
            raise WorkspacePolicyError("query must contain 1 to 500 characters")
        directory = self._resolve_existing(value) if value else self.root
        candidates = [directory] if directory.is_file() else sorted(directory.rglob("*"))
        matches: list[str] = []
        for candidate in candidates:
            if not candidate.is_file() or candidate.is_symlink():
                continue
            relative = self.relative(candidate)
            if ".git" in Path(relative).parts or candidate.stat().st_size > MAX_READ_BYTES:
                continue
            try:
                lines = candidate.read_text(encoding="utf-8").splitlines()
            except UnicodeDecodeError:
                continue
            for number, line in enumerate(lines, start=1):
                if query in line:
                    matches.append(f"{relative}:{number}:{line}")
                    if len(matches) >= MAX_SEARCH_MATCHES:
                        return WorkspaceOperationResult("\n".join(matches), relative)
        return WorkspaceOperationResult("\n".join(matches), self.relative(directory))

    def write(self, value: str, content: str) -> WorkspaceOperationResult:
        path = self._assert_target(value)
        before = path.read_bytes()
        path.write_text(content, encoding="utf-8")
        changed = before != path.read_bytes()
        return WorkspaceOperationResult("Target file updated.", self.target_path, changed)

    def replace(self, value: str, old_text: str, new_text: str) -> WorkspaceOperationResult:
        path = self._assert_target(value)
        if old_text == "":
            raise WorkspacePolicyError("old_text must not be empty")
        content = self._read_text(path)
        occurrences = content.count(old_text)
        if occurrences != 1:
            raise WorkspacePolicyError(
                f"old_text must match exactly once; observed {occurrences} matches"
            )
        path.write_text(content.replace(old_text, new_text, 1), encoding="utf-8")
        return WorkspaceOperationResult("Target file replacement applied.", self.target_path, True)

    def _assert_target(self, value: str) -> Path:
        relative = self._normalize_relative(value)
        if relative != self.target_path:
            raise WorkspacePolicyError(f"writes are permitted only to {self.target_path}")
        path = self._resolve_existing(relative)
        if path != self.target or not path.is_file() or (self.root / relative).is_symlink():
            raise WorkspacePolicyError("target binding changed during the attempt")
        return path

    def relative(self, path: Path) -> str:
        relative = path.relative_to(self.root).as_posix()
        return relative or "."

    @staticmethod
    def sha256(value: str) -> str:
        return hashlib.sha256(value.encode("utf-8")).hexdigest()
