import io
import stat
import zipfile
from pathlib import PurePosixPath

import uvicorn
from fastapi import FastAPI, File, UploadFile
from fastapi.responses import JSONResponse, PlainTextResponse

app = FastAPI()
MAX_MEMBERS = 128
MAX_EXPANDED_BYTES = 5 * 1024 * 1024


def safe_member(info: zipfile.ZipInfo) -> bool:
    path = PurePosixPath(info.filename.replace("\\", "/"))
    mode = info.external_attr >> 16
    return (
        bool(info.filename)
        and not path.is_absolute()
        and ".." not in path.parts
        and not any(":" in part for part in path.parts)
        and not stat.S_ISLNK(mode)
    )


@app.post("/convert")
async def convert(file: UploadFile = File(...)):
    try:
        data = await file.read()
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            members = archive.infolist()
            if (
                len(members) > MAX_MEMBERS
                or any(not safe_member(member) for member in members)
                or sum(member.file_size for member in members) > MAX_EXPANDED_BYTES
            ):
                raise ValueError("unsafe archive")
            output = []
            for member in members:
                if member.filename.endswith(".txt"):
                    output.append(archive.read(member).decode("utf-8"))
    except (UnicodeDecodeError, ValueError, zipfile.BadZipFile, RuntimeError):
        return JSONResponse(status_code=400, content={"error": "invalid input"})
    return PlainTextResponse("\n".join(output))


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5000)
