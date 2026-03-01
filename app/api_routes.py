from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session
from app.database import get_db, User, Repository, PRReview, ReviewComment, DeveloperScore
from app.auth import (
    exchange_code_for_token, get_github_user,
    get_github_user_repos, create_jwt_token, get_current_user
)
import os

router = APIRouter()

FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:3000")


# ── Auth Routes ───────────────────────────────────────────

@router.get("/auth/login")
async def github_login():
    """Redirect user to GitHub OAuth page."""
    client_id = os.getenv("GITHUB_CLIENT_ID")
    return RedirectResponse(
        f"https://github.com/login/oauth/authorize?client_id={client_id}&scope=repo,user"
    )


@router.get("/auth/callback")
async def github_callback(code: str, db: Session = Depends(get_db)):
    """GitHub redirects here after user authorizes."""
    
    # Exchange code for GitHub access token
    github_token = await exchange_code_for_token(code)
    
    # Fetch user profile from GitHub
    github_user = await get_github_user(github_token)
    
    # Save or update user in our database
    user = db.query(User).filter(User.github_id == str(github_user["id"])).first()
    
    if not user:
        user = User(
            github_id=str(github_user["id"]),
            username=github_user["login"],
            email=github_user.get("email", ""),
            avatar_url=github_user.get("avatar_url", ""),
            access_token=github_token
        )
        db.add(user)
    else:
        user.access_token = github_token
        user.avatar_url = github_user.get("avatar_url", "")
    
    db.commit()
    db.refresh(user)
    
    # Create JWT token for our platform
    jwt_token = create_jwt_token({
        "github_id": user.github_id,
        "username": user.username
    })
    
    # Redirect to frontend with token
    return RedirectResponse(f"{FRONTEND_URL}/dashboard?token={jwt_token}")


@router.get("/auth/me")
async def get_me(current_user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    """Get current logged in user profile."""
    user = db.query(User).filter(User.github_id == current_user["sub"]).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    return {
        "username": user.username,
        "email": user.email,
        "avatar_url": user.avatar_url,
        "created_at": user.created_at
    }


# ── Repository Routes ─────────────────────────────────────

@router.get("/repos")
async def get_user_repos(current_user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    """Get all repos connected by the current user."""
    user = db.query(User).filter(User.github_id == current_user["sub"]).first()
    repos = db.query(Repository).filter(Repository.user_id == user.id).all()
    
    return [{
        "id": r.id,
        "full_name": r.full_name,
        "language": r.language,
        "is_active": r.is_active,
        "total_reviews": len(r.reviews)
    } for r in repos]


@router.post("/repos/connect")
async def connect_repo(
    repo_data: dict,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Connect a GitHub repo to CodeSentinel."""
    user = db.query(User).filter(User.github_id == current_user["sub"]).first()
    
    existing = db.query(Repository).filter(
        Repository.full_name == repo_data["full_name"]
    ).first()
    
    if existing:
        raise HTTPException(status_code=400, detail="Repo already connected")
    
    repo = Repository(
        user_id=user.id,
        github_repo_id=str(repo_data.get("github_repo_id", "")),
        full_name=repo_data["full_name"],
        language=repo_data.get("language", ""),
        is_active=True
    )
    db.add(repo)
    db.commit()
    
    return {"message": f"Repository {repo_data['full_name']} connected successfully"}


@router.get("/repos/available")
async def get_available_repos(current_user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    """Fetch all GitHub repos the user can connect."""
    user = db.query(User).filter(User.github_id == current_user["sub"]).first()
    repos = await get_github_user_repos(user.access_token)
    
    return [{
        "full_name": r["full_name"],
        "github_repo_id": r["id"],
        "language": r.get("language", ""),
        "private": r["private"],
        "updated_at": r["updated_at"]
    } for r in repos if isinstance(r, dict)]


# ── Analytics Routes ──────────────────────────────────────

@router.get("/analytics/overview")
async def get_overview(
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get overview stats for the current user's repos."""
    user = db.query(User).filter(User.github_id == current_user["sub"]).first()
    repos = db.query(Repository).filter(Repository.user_id == user.id).all()
    repo_ids = [r.id for r in repos]
    
    reviews = db.query(PRReview).filter(PRReview.repository_id.in_(repo_ids)).all()
    
    total_reviews = len(reviews)
    total_critical = sum(r.critical_count for r in reviews)
    total_high = sum(r.high_count for r in reviews)
    avg_score = round(sum(r.quality_score for r in reviews) / total_reviews, 1) if reviews else 0
    
    approved = len([r for r in reviews if r.verdict == "APPROVE"])
    changes_requested = len([r for r in reviews if r.verdict == "REQUEST_CHANGES"])
    
    return {
        "total_reviews": total_reviews,
        "total_critical_issues": total_critical,
        "total_high_issues": total_high,
        "average_quality_score": avg_score,
        "approved_prs": approved,
        "changes_requested": changes_requested,
        "repos_connected": len(repos)
    }


@router.get("/analytics/reviews")
async def get_reviews(
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get all PR reviews for the current user."""
    user = db.query(User).filter(User.github_id == current_user["sub"]).first()
    repos = db.query(Repository).filter(Repository.user_id == user.id).all()
    repo_ids = [r.id for r in repos]
    
    reviews = db.query(PRReview).filter(
        PRReview.repository_id.in_(repo_ids)
    ).order_by(PRReview.reviewed_at.desc()).limit(50).all()
    
    return [{
        "id": r.id,
        "pr_number": r.pr_number,
        "pr_title": r.pr_title,
        "pr_author": r.pr_author,
        "verdict": r.verdict,
        "quality_score": r.quality_score,
        "critical_count": r.critical_count,
        "high_count": r.high_count,
        "medium_count": r.medium_count,
        "low_count": r.low_count,
        "reviewed_at": r.reviewed_at
    } for r in reviews]


@router.get("/analytics/developer/{username}")
async def get_developer_scorecard(
    username: str,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get developer scorecard for a specific GitHub username."""
    user = db.query(User).filter(User.github_id == current_user["sub"]).first()
    repos = db.query(Repository).filter(Repository.user_id == user.id).all()
    repo_ids = [r.id for r in repos]
    
    reviews = db.query(PRReview).filter(
        PRReview.repository_id.in_(repo_ids),
        PRReview.pr_author == username
    ).all()
    
    if not reviews:
        raise HTTPException(status_code=404, detail="No reviews found for this developer")
    
    total_prs = len(reviews)
    avg_score = round(sum(r.quality_score for r in reviews) / total_prs, 1)
    total_critical = sum(r.critical_count for r in reviews)
    total_high = sum(r.high_count for r in reviews)
    
    # Score trend — last 5 PRs
    recent_scores = [r.quality_score for r in sorted(reviews, key=lambda x: x.reviewed_at)][-5:]
    trend = "improving" if len(recent_scores) > 1 and recent_scores[-1] > recent_scores[0] else "declining" if len(recent_scores) > 1 and recent_scores[-1] < recent_scores[0] else "stable"
    
    return {
        "username": username,
        "total_prs_reviewed": total_prs,
        "average_quality_score": avg_score,
        "total_critical_issues": total_critical,
        "total_high_issues": total_high,
        "score_trend": trend,
        "recent_scores": recent_scores
    }


@router.get("/analytics/security-heatmap")
async def get_security_heatmap(
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get security issues grouped by file for heatmap visualization."""
    user = db.query(User).filter(User.github_id == current_user["sub"]).first()
    repos = db.query(Repository).filter(Repository.user_id == user.id).all()
    repo_ids = [r.id for r in repos]
    
    reviews = db.query(PRReview).filter(PRReview.repository_id.in_(repo_ids)).all()
    review_ids = [r.id for r in reviews]
    
    comments = db.query(ReviewComment).filter(
        ReviewComment.review_id.in_(review_ids),
        ReviewComment.severity.in_(["CRITICAL", "HIGH"])
    ).all()
    
    # Group by filename
    heatmap = {}
    for comment in comments:
        fname = comment.filename
        if fname not in heatmap:
            heatmap[fname] = {"critical": 0, "high": 0, "total": 0}
        if comment.severity == "CRITICAL":
            heatmap[fname]["critical"] += 1
        else:
            heatmap[fname]["high"] += 1
        heatmap[fname]["total"] += 1
    
    # Sort by total issues
    sorted_heatmap = sorted(heatmap.items(), key=lambda x: x[1]["total"], reverse=True)
    
    return [{"filename": k, **v} for k, v in sorted_heatmap]