import os
from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, Text, Boolean, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


# ── Tables ────────────────────────────────────────────────

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    github_id = Column(String, unique=True, nullable=False)
    username = Column(String, nullable=False)
    email = Column(String)
    avatar_url = Column(String)
    access_token = Column(String)           # GitHub OAuth token
    created_at = Column(DateTime, default=datetime.utcnow)

    repositories = relationship("Repository", back_populates="owner")


class Repository(Base):
    __tablename__ = "repositories"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    github_repo_id = Column(String, unique=True)
    full_name = Column(String, nullable=False)   # e.g. theraunaksingh01/ai-code-reviewer
    language = Column(String)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    owner = relationship("User", back_populates="repositories")
    reviews = relationship("PRReview", back_populates="repository")


class PRReview(Base):
    __tablename__ = "pr_reviews"

    id = Column(Integer, primary_key=True)
    repository_id = Column(Integer, ForeignKey("repositories.id"))
    pr_number = Column(Integer, nullable=False)
    pr_title = Column(String)
    pr_author = Column(String)              # GitHub username of PR author
    verdict = Column(String)               # APPROVE, REQUEST_CHANGES, COMMENT
    summary = Column(Text)
    quality_score = Column(Float)          # 0-100 score
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    reviewed_at = Column(DateTime, default=datetime.utcnow)

    repository = relationship("Repository", back_populates="reviews")
    comments = relationship("ReviewComment", back_populates="review")


class ReviewComment(Base):
    __tablename__ = "review_comments"

    id = Column(Integer, primary_key=True)
    review_id = Column(Integer, ForeignKey("pr_reviews.id"))
    filename = Column(String)
    line_number = Column(Integer)
    severity = Column(String)
    category = Column(String)
    issue = Column(Text)
    suggestion = Column(Text)
    confidence = Column(Float)

    review = relationship("PRReview", back_populates="comments")


class DeveloperScore(Base):
    __tablename__ = "developer_scores"

    id = Column(Integer, primary_key=True)
    username = Column(String, nullable=False)
    repository_id = Column(Integer, ForeignKey("repositories.id"))
    total_prs = Column(Integer, default=0)
    avg_quality_score = Column(Float, default=0.0)
    total_critical = Column(Integer, default=0)
    total_high = Column(Integer, default=0)
    total_medium = Column(Integer, default=0)
    total_low = Column(Integer, default=0)
    last_updated = Column(DateTime, default=datetime.utcnow)


# ── Helpers ───────────────────────────────────────────────

def get_db():
    """Dependency for FastAPI routes — yields a database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def create_tables():
    """Create all tables in the database."""
    Base.metadata.create_all(bind=engine)
    print("✅ Database tables created")


def calculate_quality_score(critical: int, high: int, medium: int, low: int) -> float:
    """
    Calculate PR quality score out of 100.
    Starts at 100 and deducts points per issue severity.
    """
    score = 100.0
    score -= critical * 25   # Critical issues tank the score
    score -= high * 10
    score -= medium * 5
    score -= low * 2
    return max(0.0, round(score, 1))   # Never below 0