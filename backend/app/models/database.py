"""
PhishGuard SOC - Database Models & Session
SQLAlchemy async setup with SQLite.
"""
import json
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean, Column, DateTime, Float, Integer, String, Text, ForeignKey
)
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, relationship

from app.core.config import settings

# ── Engine & session ──────────────────────────────────────────────────────────
engine = create_async_engine(settings.DATABASE_URL, echo=settings.DEBUG)
AsyncSessionLocal = async_sessionmaker(engine, expire_on_commit=False)


async def get_db():
    async with AsyncSessionLocal() as session:
        yield session


async def init_db():
    """Create all tables and seed the demo admin user."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    await _seed_demo_user()


async def _seed_demo_user():
    from app.core.security import hash_password
    from sqlalchemy import select

    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(User).where(User.username == settings.DEMO_ADMIN_USERNAME)
        )
        if result.scalar_one_or_none() is None:
            user = User(
                username=settings.DEMO_ADMIN_USERNAME,
                hashed_password=hash_password(settings.DEMO_ADMIN_PASSWORD),
                full_name="SOC Administrator",
                role="admin",
                is_active=True,
            )
            db.add(user)
            await db.commit()


# ── Base ──────────────────────────────────────────────────────────────────────
class Base(DeclarativeBase):
    pass


# ── Users ─────────────────────────────────────────────────────────────────────
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(64), unique=True, nullable=False, index=True)
    hashed_password = Column(String(256), nullable=False)
    full_name = Column(String(128), default="")
    role = Column(String(32), default="analyst")
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    analyses = relationship("Analysis", back_populates="owner")


# ── Analysis ──────────────────────────────────────────────────────────────────
class Analysis(Base):
    __tablename__ = "analyses"

    id = Column(Integer, primary_key=True, index=True)
    analysis_id = Column(String(36), unique=True, nullable=False, index=True)
    original_filename = Column(String(256), nullable=False)
    sample_type = Column(String(32), default="unknown")  # email | attachment | unknown
    upload_time = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    file_size = Column(Integer, default=0)

    # Hashes
    md5 = Column(String(32), default="")
    sha1 = Column(String(40), default="")
    sha256 = Column(String(64), default="")

    # Verdict
    score = Column(Integer, default=0)
    verdict = Column(String(32), default="Benign")
    verdict_color = Column(String(16), default="green")

    # JSON blobs
    findings_json = Column(Text, default="[]")
    iocs_json = Column(Text, default="{}")
    score_breakdown_json = Column(Text, default="{}")
    explanations_json = Column(Text, default="[]")
    mitre_json = Column(Text, default="[]")
    headers_json = Column(Text, default="{}")
    urls_json = Column(Text, default="[]")
    attachments_json = Column(Text, default="[]")

    # Paths
    report_html_path = Column(String(512), default="")
    report_json_path = Column(String(512), default="")

    # Analyst
    analyst_notes = Column(Text, default="")
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    owner = relationship("User", back_populates="analyses")

    # Helper properties
    @property
    def findings(self):
        return json.loads(self.findings_json or "[]")

    @property
    def iocs(self):
        return json.loads(self.iocs_json or "{}")

    @property
    def score_breakdown(self):
        return json.loads(self.score_breakdown_json or "{}")

    @property
    def explanations(self):
        return json.loads(self.explanations_json or "[]")

    @property
    def mitre(self):
        return json.loads(self.mitre_json or "[]")

    @property
    def headers(self):
        return json.loads(self.headers_json or "{}")

    @property
    def urls(self):
        return json.loads(self.urls_json or "[]")

    @property
    def attachments(self):
        return json.loads(self.attachments_json or "[]")
