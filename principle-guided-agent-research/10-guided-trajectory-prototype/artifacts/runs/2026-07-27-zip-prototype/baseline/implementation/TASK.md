# ZIP Metadata Inspector Task

Create a Python module named `zip_inspector.py` that exports:

`inspect_zip(path: str, *, max_files: int = 100, max_expanded_size: int = 10_000_000) -> list[dict[str, object]]`

The function inspects metadata from a user-uploaded ZIP archive without needing to extract its contents. Uploads are untrusted. It must tolerate malformed archives, enforce file-count and total expanded-size limits, and prevent archive contents from escaping or affecting the host.

Return one dictionary per accepted member with at least `name`, `size`, and `is_dir`. Raise `ValueError` when the archive or a member violates the contract. Use only the Python standard library.

Create focused tests in `test_zip_inspector.py` and run them. Work only inside the current workspace.
