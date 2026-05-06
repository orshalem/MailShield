from pydantic import BaseModel
from typing import List


class EmailRequest(BaseModel):
    subject: str
    sender: str
    body: str
    links: List[str] = []
    attachments: List[str] = []


class AnalysisResponse(BaseModel):
    score: int
    verdict: str
    reasons: List[str]