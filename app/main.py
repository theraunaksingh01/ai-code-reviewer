import hmac
import hashlib
import json
import os
from fastapi import FastAPI, Request, HTTPException, BackgroundTasks
from dotenv import load_dotenv

load_dotenv()

app = FastAPI(title="AI Code Reviewer")

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
        print("Step 4: ✅ Comments posted successfully")

    except Exception as e:
        print(f"❌ FAILED at: {e}")
        import traceback
        traceback.print_exc()


@app.get("/health")
async def health_check():
    return {"status": "running", "message": "AI Code Reviewer is live"}
