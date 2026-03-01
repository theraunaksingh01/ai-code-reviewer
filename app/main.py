import hmac
import hashlib
import json
import os
from fastapi import FastAPI, Request, HTTPException, BackgroundTasks
from dotenv import load_dotenv

from app.database import create_tables


load_dotenv()

app = FastAPI(title="AI Code Reviewer")

@app.on_event("startup")
async def startup():
    create_tables()

WEBHOOK_SECRET = os.getenv("GITHUB_WEBHOOK_SECRET")


def verify_webhook_signature(payload: bytes, signature: str) -> bool:
    """Verify that the webhook actually came from GitHub."""
    if not signature or not signature.startswith("sha256="):
        return False
    
    expected = hmac.new(
        WEBHOOK_SECRET.encode(),
        payload,
        hashlib.sha256
    ).hexdigest()
    
    return hmac.compare_digest(f"sha256={expected}", signature)


@app.post("/webhook")
async def github_webhook(request: Request, background_tasks: BackgroundTasks):
    """Main webhook endpoint — GitHub sends all events here."""
    
    payload_bytes = await request.body()
    signature = request.headers.get("X-Hub-Signature-256", "")
    
    # Security check — reject anything not from GitHub
    if not verify_webhook_signature(payload_bytes, signature):
        raise HTTPException(status_code=401, detail="Invalid signature")
    
    payload = json.loads(payload_bytes)
    event_type = request.headers.get("X-GitHub-Event")
    
    print(f"📨 Event received: {event_type}")  
    print(f"📨 Action: {payload.get('action')}")  
    
    # We only care about pull request events
    if event_type == "pull_request":
        action = payload.get("action")
        
        # Auto-index merged PRs to keep RAG updated
        if action == "closed":
            if payload["pull_request"].get("merged"):
                pr_number = payload["pull_request"]["number"]
                repo_name = payload["repository"]["full_name"]
                print(f"📚 PR #{pr_number} merged — indexing for RAG")
                background_tasks.add_task(index_merged_pr_task, repo_name, pr_number)
        
        # Trigger review when PR is opened or new commits are pushed
        if action in ["opened", "synchronize", "reopened"]:
            pr_number = payload["pull_request"]["number"]
            repo_name = payload["repository"]["full_name"]
            
            print(f"✅ Action triggered: {action}")
            print(f"🔍 New PR #{pr_number} detected in {repo_name}")
            
            # Run review in background so we respond to GitHub immediately
            # GitHub expects a response within 10 seconds or it retries
            background_tasks.add_task(handle_pr_review, repo_name, pr_number)
    
    return {"status": "received"}


async def handle_pr_review(repo_name: str, pr_number: int):
    print(f"🚀 handle_pr_review called for PR #{pr_number} in {repo_name}")
    
    try:
        print("Step 1: Importing modules...")
        from app.github_client import get_pr_diff, post_review_comment
        from app.review_pipeline import review_pull_request
        print("Step 1: ✅ Imports successful")
        
        print("Step 2: Fetching PR diff...")
        pr_data = get_pr_diff(repo_name, pr_number)
        print(f"Step 2: ✅ Fetched {len(pr_data['files'])} files")
        
        print("Step 3: Running AI review...")
        review = await review_pull_request(pr_data)
        print(f"Step 3: ✅ Review complete — {len(review['comments'])} comments")
        
        print("Step 4: Posting comments to GitHub...")
        formatted_comments = []
        for comment in review["comments"]:
            severity_emoji = {
                "CRITICAL": "🔴",
                "HIGH": "🟠",
                "MEDIUM": "🟡",
                "LOW": "🔵",
                "INFO": "⚪"
            }.get(comment["severity"], "⚪")

            body = f"""{severity_emoji} **[{comment['severity']}] {comment['category']}**

**Issue:** {comment['issue']}

**Suggested Fix:**
```
{comment['suggestion']}
```

*Confidence: {int(comment.get('confidence', 0.8) * 100)}%*"""

            formatted_comments.append({
                "filename": comment["filename"],
                "line": comment["line"],
                "body": body
            })

        verdict_emoji = {"APPROVE": "✅", "REQUEST_CHANGES": "❌", "COMMENT": "💬"}.get(review["verdict"], "💬")
        summary = f"""{verdict_emoji} **Verdict: {review['verdict']}**

{review['summary']}

---
*🤖 Reviewed by AI Code Reviewer | {len(review['comments'])} issue(s) found*"""

        post_review_comment(repo_name, pr_number, formatted_comments, summary)
        
        # Save review to database
        from app.database import SessionLocal, PRReview as PRReviewModel, ReviewComment as ReviewCommentModel, calculate_quality_score
        
        db = SessionLocal()
        try:
            # Count issues by severity
            severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
            for c in review["comments"]:
                sev = c.get("severity", "LOW")
                if sev in severity_counts:
                    severity_counts[sev] += 1
        
            quality_score = calculate_quality_score(
                severity_counts["CRITICAL"],
                severity_counts["HIGH"],
                severity_counts["MEDIUM"],
                severity_counts["LOW"]
            )
        
            # Save PR review
            pr_review = PRReviewModel(
                pr_number=pr_number,
                pr_title=pr_data["pr_title"],
                pr_author=pr_data.get("pr_author", "unknown"),
                verdict=review["verdict"],
                summary=review["summary"],
                quality_score=quality_score,
                critical_count=severity_counts["CRITICAL"],
                high_count=severity_counts["HIGH"],
                medium_count=severity_counts["MEDIUM"],
                low_count=severity_counts["LOW"]
            )
            db.add(pr_review)
            db.flush()
        
            # Save individual comments
            for comment in review["comments"]:
                db_comment = ReviewCommentModel(
                    review_id=pr_review.id,
                    filename=comment.get("filename", "unknown"),
                    line_number=comment.get("line", 0),
                    severity=comment.get("severity", "LOW"),
                    category=comment.get("category", "General"),
                    issue=comment.get("issue", ""),
                    suggestion=comment.get("suggestion", ""),
                    confidence=comment.get("confidence", 0.8)
                )
                db.add(db_comment)
        
            db.commit()
            print(f"💾 Review saved to database — Quality Score: {quality_score}/100")

        except Exception as e:
            print(f"❌ Database save failed: {e}")
            db.rollback()
        finally:
            db.close()
        print("Step 4: ✅ Comments posted successfully")

    except Exception as e:
        print(f"❌ FAILED at: {e}")
        import traceback
        traceback.print_exc()

async def index_merged_pr_task(repo_name: str, pr_number: int):
    from app.rag.indexer import index_single_merged_pr
    index_single_merged_pr(repo_name, pr_number)

@app.get("/health")
async def health_check():
    return {"status": "running", "message": "AI Code Reviewer is live"}
