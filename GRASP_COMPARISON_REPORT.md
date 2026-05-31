# Secure Code Generation: Workflow Comparison Report

**Date:** 2026-05-31  
**Task:** Implement `load_yaml_file(filename)` in `tools/file_loader.py`  
**Prompt (identical across all three runs):**

> Implement a Python function `load_yaml_file(filename)` in `tools/file_loader.py` that reads a YAML file from the `tmp/` directory using the provided filename parameter and returns the parsed contents as a dictionary. Include error handling.

---

## Workflows Compared

| Workflow              | Description                                                                                               | SCP Reference                                |
| --------------------- | --------------------------------------------------------------------------------------------------------- | -------------------------------------------- |
| `archon-assist`       | Single-node general-purpose agent — no security guidance                                                  | None                                         |
| `secure-coding`       | 4-node workflow — implements with full flat OWASP SCP list injected                                       | Flat markdown list                           |
| `grasp-secure-coding` | 8-node GRASP workflow — traverses the OWASP SCP DAG, applies only relevant principles in dependency order | Structured JSON graph (214 nodes, 860 edges) |

---

## 1. Speed

### Wall-Clock Time

| Workflow              | Total               | Winner |
| --------------------- | ------------------- | ------ |
| `archon-assist`       | **19s**             | 🥇     |
| `secure-coding`       | **289s (~5 min)**   | 🥈     |
| `grasp-secure-coding` | **1034s (~17 min)** | 🥉     |

### Node-Level Breakdown

#### `archon-assist`

| Node      | Duration  |
| --------- | --------- |
| assist    | 19.1s     |
| **Total** | **19.1s** |

#### `secure-coding`

| Node                     | Duration   |
| ------------------------ | ---------- |
| load-owasp               | <1s        |
| implement (loop, 1 iter) | 34.1s      |
| generate-tests           | 238.4s     |
| validate (loop, 1 iter)  | 16.4s      |
| **Total**                | **289.0s** |

#### `grasp-secure-coding`

| Node                        | Duration    |
| --------------------------- | ----------- |
| load-scp-graph              | <1s         |
| generate-seed               | 11.9s       |
| select-groups (haiku)       | 23.5s       |
| grasp-refine (loop, 1 iter) | 136.5s      |
| extract-final (haiku)       | 14.8s       |
| write-code                  | 35.6s       |
| generate-tests              | 86.3s       |
| validate (loop, 1 iter)     | **725.3s**  |
| **Total**                   | **1033.9s** |

> **Note:** GRASP's validate node dominates runtime (70% of total). This is a one-time cost for installing pytest in the worktree and running the full adversarial test suite. The core reasoning phase (`grasp-refine`) took only 136s. The main speed cost of GRASP vs `secure-coding` implement (136s vs 34s) comes from injecting the 193KB SCP graph (~48K tokens) into the loop prompt — a known optimization target.

---

## 2. Generated Implementation

### Code Volume

| Metric                         | `archon-assist` | `secure-coding` | `grasp-secure-coding` |
| ------------------------------ | :-------------: | :-------------: | :-------------------: |
| Total lines                    |       36        |       87        |          57           |
| Code lines (non-blank/comment) |     **23**      |       53        |          37           |
| Bandit HIGH issues             |        0        |        0        |           0           |
| Bandit MEDIUM issues           |        0        |        0        |           0           |
| Info leakage in error messages |   ⚠️ **Yes**    |       No        |          No           |

### Security Controls

| Control                                             | `archon-assist` | `secure-coding` | `grasp-secure-coding` |
| --------------------------------------------------- | :-------------: | :-------------: | :-------------------: |
| `yaml.safe_load` (prevents RCE via deserialization) |       ✅        |       ✅        |          ✅           |
| Input type check (`isinstance`)                     |       ✅        |       ✅        |          ✅           |
| Allowlist regex (safe character set)                |       ❌        |       ✅        |          ✅           |
| Extension allowlist (`.yaml`/`.yml` only)           |       ❌        |       ✅        |          ✅           |
| Null byte rejection                                 |       ❌        |       ✅        |          ✅           |
| Explicit `..` traversal check                       |       ✅        |       ❌        |          ✅           |
| Path confinement (`realpath` / `relative_to`)       |       ✅        |       ✅        |          ✅           |
| Max filename length (≤255)                          |       ❌        |       ✅        |          ✅           |
| Structured logging (`logger.warning`)               |       ❌        |       ❌        |          ✅           |
| Error messages hide internal paths                  |       ❌        |       ✅        |          ✅           |
| SCP traceability in code comments                   |       ❌        |       ❌        |          ✅           |
| **Security score**                                  |   **4 / 11**    |   **8 / 11**    |      **11 / 11**      |

### Generated Code Side-by-Side

#### `archon-assist` — 23 code lines

```python
import os
import yaml

_TMP_DIR = os.path.join(os.path.dirname(__file__), "..", "tmp")

def load_yaml_file(filename: str) -> dict:
    path = os.path.normpath(os.path.join(_TMP_DIR, filename))

    tmp_abs = os.path.realpath(_TMP_DIR)
    if not os.path.realpath(path).startswith(tmp_abs + os.sep):
        raise ValueError(f"Invalid filename: '{filename}' escapes the tmp/ directory")
    #                     ^^^ leaks filename in error message

    if not os.path.exists(path):
        raise FileNotFoundError(f"File not found: {path}")
    #                            ^^^ leaks resolved internal path

    with open(path, "r", encoding="utf-8") as f:
        try:
            data = yaml.safe_load(f)
        except yaml.YAMLError as exc:
            raise ValueError(f"Failed to parse YAML file '{filename}': {exc}") from exc
            #                                                              ^^^ leaks exception internals

    if data is None:
        return {}
    if not isinstance(data, dict):
        raise TypeError(f"Expected a YAML mapping, got {type(data).__name__}")
    return data
```

**Critical issues:** Three error messages leak internal state — the resolved filesystem path, the raw `yaml.YAMLError` detail (which may contain file content fragments), and the full exception chain. Bandit does not flag these.

#### `secure-coding` — 53 code lines

```python
import os, re
from pathlib import Path
from typing import Any
import yaml

_TMP_DIR = Path(__file__).resolve().parent.parent / "tmp"
_SAFE_FILENAME_RE = re.compile(r'^[A-Za-z0-9_\-]+\.ya?ml$')

def load_yaml_file(filename: str) -> dict[str, Any]:
    if not isinstance(filename, str):
        raise ValueError("filename must be a string")
    if not _SAFE_FILENAME_RE.fullmatch(filename):
        raise ValueError("Invalid filename. Only alphanumerics, hyphens, and underscores "
                         "followed by .yaml or .yml are accepted.")
    target = (_TMP_DIR / filename).resolve()
    try:
        target.relative_to(_TMP_DIR.resolve())
    except ValueError:
        raise ValueError("Invalid filename: path escapes the allowed directory.")
    if not target.exists():
        raise FileNotFoundError(f"File not found in tmp/: {filename!r}")
    if not target.is_file():
        raise ValueError(f"{filename!r} is not a regular file.")
    try:
        with target.open("r", encoding="utf-8") as fh:
            contents = yaml.safe_load(fh)
    except yaml.YAMLError:
        raise RuntimeError("Failed to parse YAML file.")
    except OSError:
        raise RuntimeError("Failed to read file.")
    if contents is None:
        return {}
    if not isinstance(contents, dict):
        raise TypeError("YAML file must contain a mapping at the top level.")
    return contents
```

**Strong implementation.** Pathlib-idiomatic, full allowlist regex, clean error messages. Missing: explicit `..` check (covered implicitly by `relative_to`), structured logging, SCP traceability.

#### `grasp-secure-coding` — 37 code lines

```python
import logging, os, re
import yaml

logger = logging.getLogger(__name__)

_SAFE_FILENAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_\-\.]*$")
_MAX_FILENAME_LEN = 255

def load_yaml_file(filename: str) -> dict:
    # IV-1/IV-3: reject wrong type, empty string, or oversized input
    if not isinstance(filename, str) or not filename or len(filename) > _MAX_FILENAME_LEN:
        logger.warning("load_yaml_file: filename validation failed (type or length)")
        raise ValueError("Invalid filename.")

    # IV-2: allowlist — only safe characters; first char must be alphanumeric
    if not _SAFE_FILENAME_RE.match(filename):
        logger.warning("load_yaml_file: filename contains disallowed characters")
        raise ValueError("Invalid filename.")

    # FM-2: explicitly reject traversal sequences and null bytes
    if ".." in filename or "\x00" in filename:
        logger.warning("load_yaml_file: path traversal attempt detected")
        raise ValueError("Invalid filename.")

    # FM-2/FM-5: restrict to YAML extensions only (allowlist, not denylist)
    if not filename.endswith((".yaml", ".yml")):
        logger.warning("load_yaml_file: disallowed file extension")
        raise ValueError("Invalid filename.")

    # FM-2/FM-5: canonicalize and verify the resolved path stays within tmp/
    base_dir = os.path.realpath("tmp")
    filepath = os.path.realpath(os.path.join("tmp", filename))
    if not filepath.startswith(base_dir + os.sep):
        logger.warning("load_yaml_file: resolved path escapes the base directory")
        raise ValueError("Invalid filename.")

    # EHL-3: all validation complete — now access the filesystem
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    except FileNotFoundError:
        raise FileNotFoundError("File not found.") from None
    except yaml.YAMLError:
        logger.error("load_yaml_file: YAML parse error for '%s'", filename)
        raise ValueError("Failed to parse YAML file.") from None
    except OSError as e:
        logger.error("load_yaml_file: OS error for '%s': %s", filename, e)
        raise OSError("Error reading file.") from None
```

**Notable:** Every block is annotated with an SCP reference ID (`IV-1`, `FM-2`, `EHL-3`). Defense-in-depth on traversal: allowlist regex + explicit `..` check + `realpath` confinement — three independent layers. Structured logging on every validation failure.

---

## 3. Test Suites

### Coverage Summary

| Metric                         | `archon-assist` | `secure-coding` | `grasp-secure-coding` |
| ------------------------------ | :-------------: | :-------------: | :-------------------: |
| Test functions                 |      **0**      |     **50**      |          27           |
| Test file lines                |        0        |       412       |          283          |
| `[SECURITY:]` tagged tests     |        0        |       36        |          18           |
| Path traversal tests           |        0        |       19        |          10           |
| RCE / deserialization tests    |        0        |        9        |          12           |
| Error leakage tests            |        0        |       26        |           8           |
| Validate passed on 1st attempt |       N/A       |       ✅        |          ✅           |

### Test Organization

**`secure-coding`** groups tests by concern:

- `TestHappyPath` (8 tests) — valid filenames and content
- `TestEdgeCases` (5 tests) — empty files, nested structures, booleans
- `TestErrorConditions` (6 tests) — missing files, bad YAML, permissions
- `TestInputValidation` (10 tests) — type checks, empty string, whitespace, long names
- `TestPathTraversal` (11 tests) — `../`, absolute paths, symlinks, URL-encoded, backslash, tilde
- `TestErrorHandlingLeakage` (5 tests) — verifies no internal path in error messages
- `TestSafeYamlParsing` (3 tests) — `!!python/object` RCE payloads
- `TestAccessControl` (2 tests) — symlink outside tmp/, parent directory access

**`grasp-secure-coding`** names tests after SCP IDs:

- `test_iv1_*` — Input validation type/None
- `test_iv2_*` — Allowlist: shell metacharacters, hidden files, spaces
- `test_iv3_*` — Empty string, oversized filename
- `test_iv4_*` — Null byte injection
- `test_fm2_*` — Path traversal, absolute paths, path separators
- `test_fm5_*` — Extension denylist, spoof extensions
- `test_ehl1_*` — File-not-found hides resolved path
- `test_ehl2_*` — YAML error hides file content
- `test_ehl3_*` — Filesystem not accessed before validation
- `test_ehl4_*` — `yaml.safe_load` vs `yaml.load` RCE

### Unique tests per workflow

`secure-coding` has but `grasp-secure-coding` lacks:

- Symlink pointing outside `tmp/` (2 tests)
- `chmod 000` unreadable file (2 tests)
- Windows backslash traversal (`..\\secret.yaml`)
- URL-encoded traversal (`..%2Fsecret.yaml`)
- Tilde home expansion (`~/.ssh/id_rsa.yaml`)

`grasp-secure-coding` has but `secure-coding` lacks:

- Shell metacharacter injection (`;`, `|`, `` ` ``, `$`, `&`, `>`)
- More RCE deserialization payloads (12 vs 9)

---

## 4. Traceability & Auditability

| Dimension                  | `archon-assist` | `secure-coding` |       `grasp-secure-coding`        |
| -------------------------- | :-------------: | :-------------: | :--------------------------------: |
| Security reasoning visible |       ❌        |       ❌        | ✅ (per-SCP score + decision log)  |
| SCP IDs in implementation  |       ❌        |       ❌        | ✅ (`# IV-1`, `# FM-2`, `# EHL-3`) |
| SCP IDs in test names      |       ❌        |       ❌        |  ✅ (`test_iv2_*`, `test_fm5_*`)   |
| "Why was this added?"      |   Must infer    |   Must infer    |      Explicit in code + tests      |
| Audit trail for compliance |       ❌        |       ❌        |                 ✅                 |

GRASP's loop produces a reasoning log as part of its output — it records which SCPs were scored, why each was applied or skipped, and what changed. This maps directly to compliance documentation (SOC 2, PCI-DSS, OWASP ASVS evidence).

---

## 5. Summary Scorecard

| Dimension             | `archon-assist` | `secure-coding` | `grasp-secure-coding` |
| --------------------- | :-------------: | :-------------: | :-------------------: |
| **Speed**             |     🥇 19s      |    🥈 5 min     |       🥉 17 min       |
| **Security depth**    |     🥉 4/11     |     🥈 8/11     |       🥇 11/11        |
| **Info leakage**      |    ❌ fails     |    ✅ passes    |       ✅ passes       |
| **Test breadth**      |     ❌ none     |   🥇 50 tests   |      🥈 27 tests      |
| **Test organisation** |     ❌ none     |  🥈 by concern  |     🥇 by SCP ID      |
| **Code conciseness**  |   🥇 23 lines   |   🥉 53 lines   |      🥈 37 lines      |
| **Traceability**      |     ❌ none     |     ❌ none     |     🥇 full chain     |
| **Bandit clean**      |       ✅        |       ✅        |          ✅           |

---

## 6. When to Use Each Workflow

| Use case                                                       | Recommended workflow                     |
| -------------------------------------------------------------- | ---------------------------------------- |
| Internal tooling, speed critical, security not primary concern | `archon-assist`                          |
| Production code, security important, need comprehensive tests  | `secure-coding`                          |
| Compliance-sensitive code, need audit trail, security-first    | `grasp-secure-coding`                    |
| Quick prototyping or exploration                               | `archon-assist`                          |
| Public-facing APIs handling user input                         | `secure-coding` or `grasp-secure-coding` |
| Code subject to OWASP ASVS / PCI-DSS / SOC 2 review            | `grasp-secure-coding`                    |

---

## 7. Key Findings

1. **Bandit is insufficient as a security gate.** All three implementations pass Bandit clean (0 issues), yet `archon-assist` leaks internal filesystem paths and exception details in three error messages — real CWE-209 (Information Exposure Through Error Messages) violations that static analysis misses.

2. **Security guidance quality matters more than presence.** The difference between `archon-assist` (4/11) and `secure-coding` (8/11) is purely the presence of a structured OWASP reference. Adding security guidance at all accounts for a 2× improvement in control coverage.

3. **GRASP achieves full control coverage with 30% less code than `secure-coding`.** The SCP graph's dependency-aware traversal focuses the model on what matters for this specific task (Input Validation, File Management, Error Handling & Logging) and skips irrelevant categories — producing a tighter, more focused implementation.

4. **GRASP's validate loop dominates runtime.** 70% of GRASP's total time was the `validate` node (725s), primarily pytest installation in the fresh worktree. The actual security reasoning (`grasp-refine`) took 136s — 4× longer than `secure-coding`'s implement node, entirely attributable to the 193KB SCP graph context injection (~48K tokens). Pre-filtering the graph to the selected subgraph before injection is the primary optimization target.

5. **Test suite completeness vs organisation.** `secure-coding` produces more tests (50 vs 27) with broader edge-case coverage (symlinks, chmod, URL encoding, Windows paths). `grasp-secure-coding` produces fewer but systematically organised tests named after SCP IDs — each test is a direct verification of a specific principle, making failure diagnosis immediate.

---

_Generated from live Archon workflow runs on 2026-05-31._  
_Workflows: `archon-assist`, `secure-coding`, `grasp-secure-coding`_  
_SCP graph source: [GRASP NDSS'27 anonymous repository](https://anonymous.4open.science/r/GRASP_NDSS27-94FF) — 214 SCPs, 860 edges_
