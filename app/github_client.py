import os
from github import GithubIntegration, Github
from dotenv import load_dotenv

load_dotenv()

APP_ID = os.getenv("GITHUB_APP_ID")
PRIVATE_KEY_PATH = os.getenv("GITHUB_PRIVATE_KEY_PATH")

with open(PRIVATE_KEY_PATH, "r") as f:
    PRIVATE_KEY = f.read()


def get_github_client(repo_name: str):
    """Authenticate as GitHub App and return a client for the specific repo."""
    integration = GithubIntegration(APP_ID, PRIVATE_KEY)
    owner = repo_name.split("/")[0]
    
    # Get installation ID for this repo
    installation = integration.get_installation(owner, repo_name.split("/")[1])
    access_token = integration.get_access_token(installation.id).token
    
    return Github(access_token)


def get_pr_diff(repo_name: str, pr_number: int):
    """Fetch all changed files and their diffs from a PR."""
    client = get_github_client(repo_name)
    repo = client.get_repo(repo_name)
    pr = repo.get_pull(pr_number)
    
    files = []
    for f in pr.get_files():
        files.append({
            "filename": f.filename,
            "status": f.status,        # added, modified, removed
            "additions": f.additions,
            "deletions": f.deletions,
            "patch": f.patch or "",    # the actual diff
        })
    
    return {
        "pr_title": pr.title,
        "pr_body": pr.body or "",
        "base_branch": pr.base.ref,
        "head_branch": pr.head.ref,
        "pr_author": pr.user.login,   
        "files": files
    }


def post_review_comment(repo_name: str, pr_number: int, comments: list, summary: str):
    """Post the AI review as comments on the PR."""
    client = get_github_client(repo_name)
    repo = client.get_repo(repo_name)
    pr = repo.get_pull(pr_number)
    
    # Post overall summary as a regular PR comment
    pr.create_issue_comment(f"## 🤖 AI Code Review\n\n{summary}")
    
    # Post inline comments on specific lines
    commit = repo.get_commit(pr.head.sha)
    for comment in comments:
        try:
            pr.create_review_comment(
                body=comment["body"],
                commit=commit,
                path=comment["filename"],
                line=comment["line"]
            )
        except Exception as e:
            print(f"Could not post inline comment: {e}")
            # Fall back to regular comment if inline fails
            pr.create_issue_comment(
                f"**{comment['filename']} (line {comment['line']}):**\n\n{comment['body']}"
            )