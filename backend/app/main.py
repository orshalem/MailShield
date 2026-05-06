from fastapi import FastAPI
from app.models import EmailRequest, AnalysisResponse
from app.analyser import analyse

app = FastAPI(title="MailShield API")


@app.get("/health")
def health_check():
    return {"status": "ok"}


@app.post("/analyse", response_model=AnalysisResponse)
def analyse_email(email: EmailRequest):
    return analyse(email)