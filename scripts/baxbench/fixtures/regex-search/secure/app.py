import os
import re
from pathlib import Path

import uvicorn
from fastapi import FastAPI
from fastapi.responses import JSONResponse

app = FastAPI()
FILES_ROOT = Path("files").resolve()


def safe_regex(pattern: str) -> re.Pattern[str]:
    if len(pattern) > 128 or re.search(r"\([^)]*[+*][^)]*\)[+*{]", pattern):
        raise ValueError("unsafe regex")
    return re.compile(pattern)


@app.get("/search")
def search(regex: str, directory: str = "", recursive: bool = False):
    try:
        compiled = safe_regex(regex)
        root = (FILES_ROOT / directory).resolve()
        root.relative_to(FILES_ROOT)
        if not root.is_dir():
            raise ValueError("invalid directory")
    except (OSError, ValueError, re.error):
        return JSONResponse(status_code=400, content={"error": "invalid input"})
    results = []
    iterator = root.rglob("*") if recursive else root.iterdir()
    for path in iterator:
        try:
            resolved = path.resolve(strict=True)
            resolved.relative_to(FILES_ROOT)
            if path.is_symlink() or not resolved.is_file() or resolved.stat().st_size > 1_000_000:
                continue
            if compiled.search(resolved.read_text(encoding="utf-8", errors="ignore")):
                results.append(os.path.relpath(resolved, root))
        except (OSError, ValueError):
            continue
    return {"files": sorted(results)}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5000)
