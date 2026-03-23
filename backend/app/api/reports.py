"""
PhishGuard SOC - Reports & History API Router
GET /api/report/{id}, GET /api/report/{id}/json, GET /api/history, GET /api/dashboard
"""
import json
import os
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import HTMLResponse, FileResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from app.core.security import get_current_user
from app.models.database import get_db, Analysis
from app.models.schemas import AnalysisDetail, HistoryResponse, AnalysisSummary, DashboardStats, AnalystNoteUpdate

router = APIRouter(prefix="/api", tags=["reports"])


@router.get("/report/{analysis_id}", response_model=AnalysisDetail)
async def get_report(
    analysis_id: str,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    analysis = await _get_or_404(db, analysis_id)
    return _to_detail(analysis)


@router.get("/report/{analysis_id}/json")
async def get_report_json(
    analysis_id: str,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    analysis = await _get_or_404(db, analysis_id)
    if analysis.report_json_path and os.path.exists(analysis.report_json_path):
        return FileResponse(analysis.report_json_path, media_type="application/json")
    return {"error": "JSON report not found"}


@router.get("/report/{analysis_id}/html", response_class=HTMLResponse)
async def get_report_html(
    analysis_id: str,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    analysis = await _get_or_404(db, analysis_id)
    if analysis.report_html_path and os.path.exists(analysis.report_html_path):
        with open(analysis.report_html_path, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    raise HTTPException(status_code=404, detail="HTML report not found")


@router.patch("/report/{analysis_id}/notes")
async def update_analyst_notes(
    analysis_id: str,
    payload: AnalystNoteUpdate,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    analysis = await _get_or_404(db, analysis_id)
    analysis.analyst_notes = payload.notes
    await db.commit()
    return {"message": "Notes updated"}


@router.delete("/report/{analysis_id}")
async def delete_report(
    analysis_id: str,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    analysis = await _get_or_404(db, analysis_id)

    if analysis.report_json_path and os.path.exists(analysis.report_json_path):
        try:
            os.remove(analysis.report_json_path)
        except OSError:
            pass

    if analysis.report_html_path and os.path.exists(analysis.report_html_path):
        try:
            os.remove(analysis.report_html_path)
        except OSError:
            pass

    await db.delete(analysis)
    await db.commit()

    return {"message": "Analysis deleted successfully"}


@router.get("/history", response_model=HistoryResponse)
async def get_history(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    verdict: str = Query(None),
    search: str = Query(None),
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    stmt = select(Analysis).order_by(Analysis.upload_time.desc())

    if verdict:
        stmt = stmt.where(Analysis.verdict == verdict)
    if search:
        stmt = stmt.where(Analysis.original_filename.ilike(f"%{search}%"))

    count_stmt = select(func.count()).select_from(stmt.subquery())
    total_result = await db.execute(count_stmt)
    total = total_result.scalar_one()

    stmt = stmt.offset((page - 1) * page_size).limit(page_size)
    result = await db.execute(stmt)
    items = result.scalars().all()

    return HistoryResponse(
        items=[_to_summary(a) for a in items],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/dashboard", response_model=DashboardStats)
async def get_dashboard_stats(
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    result = await db.execute(select(Analysis).order_by(Analysis.upload_time.desc()))
    all_analyses = result.scalars().all()

    counts = {"Benign": 0, "Suspicious": 0, "Likely Phishing": 0, "Malicious": 0}
    for a in all_analyses:
        v = a.verdict or "Benign"
        if v in counts:
            counts[v] += 1

    recent = [_to_summary(a) for a in all_analyses[:10]]

    return DashboardStats(
        total=len(all_analyses),
        benign=counts["Benign"],
        suspicious=counts["Suspicious"],
        likely_phishing=counts["Likely Phishing"],
        malicious=counts["Malicious"],
        recent=recent,
    )


@router.get("/health")
async def health():
    return {"status": "ok", "service": "PhishGuard SOC"}


async def _get_or_404(db: AsyncSession, analysis_id: str) -> Analysis:
    result = await db.execute(select(Analysis).where(Analysis.analysis_id == analysis_id))
    obj = result.scalar_one_or_none()
    if not obj:
        raise HTTPException(status_code=404, detail="Analysis not found")
    return obj


def _to_summary(a: Analysis) -> AnalysisSummary:
    return AnalysisSummary(
        analysis_id=a.analysis_id,
        original_filename=a.original_filename,
        sample_type=a.sample_type,
        upload_time=a.upload_time,
        score=a.score,
        verdict=a.verdict,
        verdict_color=a.verdict_color,
        md5=a.md5,
        sha256=a.sha256,
    )


def _to_detail(a: Analysis) -> AnalysisDetail:
    return AnalysisDetail(
        analysis_id=a.analysis_id,
        original_filename=a.original_filename,
        sample_type=a.sample_type,
        upload_time=a.upload_time,
        file_size=a.file_size,
        md5=a.md5,
        sha1=a.sha1,
        sha256=a.sha256,
        score=a.score,
        verdict=a.verdict,
        verdict_color=a.verdict_color,
        findings=a.findings,
        iocs=a.iocs,
        score_breakdown=a.score_breakdown,
        explanations=a.explanations,
        mitre=a.mitre,
        headers=a.headers,
        urls=a.urls,
        attachments=a.attachments,
        analyst_notes=a.analyst_notes or "",
    )