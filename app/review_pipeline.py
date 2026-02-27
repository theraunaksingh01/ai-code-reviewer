import os
from langchain_groq import ChatGroq
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import JsonOutputParser
from langchain_core.output_parsers import JsonOutputParser
from pydantic import BaseModel, Field
from typing import List
from dotenv import load_dotenv
from app.security.detectors import scan_file_for_security_issues, format_security_issues_for_ai

load_dotenv()


# Define the structure of each review comment
class ReviewComment(BaseModel):
    filename: str = Field(description="File being reviewed")
    line: int = Field(description="Line number of the issue")
    severity: str = Field(description="CRITICAL, HIGH, MEDIUM, LOW, or INFO")
    category: str = Field(description="Bug, Security, Performance, Style, etc.")
    issue: str = Field(description="Clear explanation of the problem")
    suggestion: str = Field(description="The fixed code or specific solution")
    confidence: float = Field(description="How confident the AI is, from 0.0 to 1.0")


class PRReview(BaseModel):
    summary: str = Field(description="Overall PR summary and assessment")
    verdict: str = Field(description="APPROVE, REQUEST_CHANGES, or COMMENT")
    comments: List[ReviewComment]


# Initialize Groq LLM
llm = ChatGroq(
    api_key=os.getenv("GROQ_API_KEY"),
    model="llama-3.3-70b-versatile",
    temperature=0.2,   # Low temperature = more consistent, focused reviews
)

parser = JsonOutputParser(pydantic_object=PRReview)


REVIEW_PROMPT = ChatPromptTemplate.from_messages([
    ("system", """You are a senior software engineer conducting a thorough code review.
Your job is to review pull request diffs and provide specific, actionable feedback.

REVIEW PRIORITIES (in order):
1. Security vulnerabilities — SQL injection, exposed secrets, XSS, command injection
2. Bugs — logic errors, null pointer issues, incorrect conditions, off-by-one errors  
3. Performance — N+1 queries, unnecessary loops, memory leaks
4. Code quality — code smells, duplicate code, overly complex logic
5. Style — naming conventions, readability

RULES:
- Only comment on ADDED lines (lines with + in the diff)
- Be specific — reference exact line numbers
- Always provide the fixed code, not just a description of the problem
- Categorize severity honestly: CRITICAL (security/data loss), HIGH (bugs), MEDIUM (performance), LOW (style)
- Set confidence between 0.0 and 1.0 based on how certain you are
- If the code looks good, say so in the summary — don't invent issues

{security_context}

Respond ONLY with valid JSON matching this format:
{format_instructions}
"""),
    ("human", """Review this pull request:

**PR Title:** {pr_title}
**PR Description:** {pr_body}
**Base Branch:** {base_branch}

**Changed Files:**
{files_content}
""")
])


def format_files_for_prompt(files: list) -> str:
    """Format PR files into a readable string for the prompt."""
    formatted = ""
    for file in files:
        formatted += f"\n### File: {file['filename']} ({file['status']})\n"
        formatted += f"Additions: {file['additions']}, Deletions: {file['deletions']}\n"
        formatted += "```diff\n"
        formatted += file['patch'][:3000]  # Limit per file to avoid token overflow
        formatted += "\n```\n"
    return formatted


async def review_pull_request(pr_data: dict) -> dict:
    """Main function — takes PR data and returns a full review."""
    
    # Step 1 — Run static security analysis on every file
    all_security_issues = []
    for file in pr_data["files"]:
        issues = scan_file_for_security_issues(file["filename"], file["patch"])
        all_security_issues.extend(issues)
    
    security_context = format_security_issues_for_ai(all_security_issues)
    
    # Step 2 — Format files for the AI prompt
    files_content = format_files_for_prompt(pr_data["files"])
    
    # Step 3 — Run AI review
    chain = REVIEW_PROMPT | llm | parser
    
    try:
        result = await chain.ainvoke({
            "pr_title": pr_data["pr_title"],
            "pr_body": pr_data["pr_body"],
            "base_branch": pr_data["base_branch"],
            "files_content": files_content,
            "security_context": security_context,
            "format_instructions": parser.get_format_instructions()
        })
    except Exception as e:
        print(f"AI review failed: {e}")
        result = {
            "summary": "AI review encountered an error. Manual review required.",
            "verdict": "COMMENT",
            "comments": []
        }
    
    # Step 4 — Merge static security findings with AI findings
    for issue in all_security_issues:
    # Find which file this issue belongs to
        affected_file = pr_data["files"][0]["filename"] if pr_data["files"] else "unknown"
        result["comments"].append({
            "filename": affected_file,
            "line": issue.line_number,
            "severity": issue.severity,
            "category": issue.category,
            "issue": issue.description,
            "suggestion": issue.recommendation,
            "confidence": 0.95
        })
    
    return result