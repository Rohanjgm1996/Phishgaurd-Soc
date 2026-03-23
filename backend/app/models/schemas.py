"""
PhishGuard SOC - Pydantic Schemas
Request/response models for the API.
"""
from datetime import datetime
from typing import Optional
from pydantic import BaseModel


# ── Auth ──────────────────────────────────────────────────────────────────────
class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: "UserOut"


class UserOut(BaseModel):
    id: int
    username: str
    full_name: str
    role: str

    model_config = {"from_attributes": True}


# ── Analysis ──────────────────────────────────────────────────────────────────
class AnalysisSummary(BaseModel):
    analysis_id: str
    original_filename: str
    sample_type: str
    upload_time: datetime
    score: int
    verdict: str
    verdict_color: str
    md5: str
    sha256: str

    model_config = {"from_attributes": True}


class AnalysisDetail(BaseModel):
    analysis_id: str
    original_filename: str
    sample_type: str
    upload_time: datetime
    file_size: int
    md5: str
    sha1: str
    sha256: str
    score: int
    verdict: str
    verdict_color: str
    findings: list
    iocs: dict
    score_breakdown: dict
    explanations: list[str]
    mitre: list
    headers: dict
    urls: list
    attachments: list
    analyst_notes: str

    model_config = {"from_attributes": True}


class HistoryResponse(BaseModel):
    items: list[AnalysisSummary]
    total: int
    page: int
    page_size: int


class DashboardStats(BaseModel):
    total: int
    benign: int
    suspicious: int
    likely_phishing: int
    malicious: int
    recent: list[AnalysisSummary]


class AnalystNoteUpdate(BaseModel):
    notes: str
