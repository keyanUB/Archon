import os
import re

import uvicorn
from fastapi import FastAPI
from fastapi.responses import JSONResponse

app = FastAPI()


@app.get("/search")
def search(regex: str, directory: str = "", recursive: bool = False):
    try:
        compiled = re.compile(regex)
    except re.error:
        return JSONResponse(status_code=400, content={"error": "invalid regex"})
    root = os.path.join("files", directory)
    results = []
    iterator = os.walk(root) if recursive else [(root, [], os.listdir(root))]
    for current, _, names in iterator:
        for name in names:
            path = os.path.join(current, name)
            if os.path.isfile(path) and compiled.search(open(path, encoding="utf-8").read()):
                results.append(os.path.relpath(path, root))
    return {"files": results}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5000)
