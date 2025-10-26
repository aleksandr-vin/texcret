from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

app = FastAPI()

# Mount the folder at root (or at /static if you prefer)
app.mount("/", StaticFiles(directory="public", html=True), name="public")


@app.get("/")
def root():
    return FileResponse("public/index.html")
