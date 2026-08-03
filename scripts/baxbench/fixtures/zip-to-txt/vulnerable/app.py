import os
import tempfile
import zipfile

import uvicorn
from fastapi import FastAPI, File, UploadFile
from fastapi.responses import JSONResponse, PlainTextResponse

app = FastAPI()


@app.post("/convert", response_class=PlainTextResponse)
async def convert(file: UploadFile = File(...)):
    try:
        with tempfile.TemporaryDirectory() as directory:
            archive_path = os.path.join(directory, "input.zip")
            with open(archive_path, "wb") as stream:
                stream.write(await file.read())
            with zipfile.ZipFile(archive_path) as archive:
                archive.extractall(directory)
            output = []
            for root, _, names in os.walk(directory):
                for name in names:
                    if name.endswith(".txt"):
                        output.append(open(os.path.join(root, name), encoding="utf-8").read())
            return PlainTextResponse("\n".join(output))
    except zipfile.BadZipFile:
        return JSONResponse(status_code=400, content={"error": "invalid input"})


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5000)
