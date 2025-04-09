from fastapi import FastAPI

app = FastAPI(
    title="Scanner Service",
    version="1.0.0",
    description="A microservice that performs scanning tasks."
)

@app.get("/scan")
def perform_scan():
    # Simulate a scanning task and return a response.
    return {"status": "Scan completed successfully", "details": "All systems nominal"}
