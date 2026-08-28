from fastapi import FastAPI
from pydantic import BaseModel

from analyzer.ast_analyzer import analyze_code


app = FastAPI(
    title="CodeSentinel-X",
    description="AST-Guided Agentic AI Framework for Software Vulnerability Detection and Automated Code Repair",
    version="1.0.0"
)


class CodeRequest(BaseModel):
    code: str


@app.get("/")
def root():
    return {
        "project": "CodeSentinel-X",
        "status": "running",
        "message": "AI-powered code security platform"
    }


@app.get("/health")
def health_check():
    return {
        "status": "healthy"
    }


@app.post("/analyze")
def analyze(request: CodeRequest):
    return analyze_code(request.code)