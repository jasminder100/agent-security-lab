from fastapi import FastAPI

app = FastAPI(title="DataOps Pipeline Assistant")


@app.get("/health")
def health():
    return {"status": "ok"}
