import re
from dataclasses import dataclass
from typing import List


@dataclass
class SecurityIssue:
    severity: str        # CRITICAL, HIGH, MEDIUM, LOW
    category: str        # SQL Injection, Exposed Secret, etc.
    line_number: int
    line_content: str
    description: str
    recommendation: str


# Patterns that indicate security vulnerabilities
SECURITY_PATTERNS = [
    {
        "category": "Exposed API Key / Secret",
        "severity": "CRITICAL",
        "patterns": [
            r'api[_-]?key\s*=\s*["\'][a-zA-Z0-9]{16,}["\']',
            r'secret[_-]?key\s*=\s*["\'][a-zA-Z0-9]{16,}["\']',
            r'password\s*=\s*["\'][^"\']{6,}["\']',
            r'token\s*=\s*["\'][a-zA-Z0-9]{16,}["\']',
            r'sk-[a-zA-Z0-9]{32,}',          # OpenAI keys
            r'ghp_[a-zA-Z0-9]{36}',           # GitHub personal tokens
            r'AKIA[0-9A-Z]{16}',              # AWS access keys
        ],
        "recommendation": "Never hardcode secrets. Use environment variables and a secrets manager."
    },
    {
        "category": "SQL Injection",
        "severity": "CRITICAL",
        "patterns": [
            r'execute\s*\(\s*["\'].*?\%s.*?["\'].*?\%',
            r'execute\s*\(\s*f["\'].*?{.*?}.*?["\']',
            r'cursor\.execute\s*\(\s*["\']SELECT.*?\+',
            r'query\s*=\s*["\']SELECT.*?\+\s*\w+',
            r'raw\s*\(\s*["\'].*?\+',
        ],
        "recommendation": "Use parameterized queries or ORM methods. Never concatenate user input into SQL strings."
    },
    {
        "category": "Cross-Site Scripting (XSS)",
        "severity": "HIGH",
        "patterns": [
            r'innerHTML\s*=\s*\w+',
            r'document\.write\s*\(\s*\w+',
            r'eval\s*\(\s*\w+',
            r'dangerouslySetInnerHTML',
        ],
        "recommendation": "Sanitize all user input before rendering. Use safe DOM methods like textContent."
    },
    {
        "category": "Path Traversal",
        "severity": "HIGH",
        "patterns": [
            r'open\s*\(\s*\w*\s*\+',
            r'open\s*\(\s*f["\'].*?{.*?}',
            r'os\.path\.join\s*\(.*?request\.',
            r'file_path\s*=.*?request\.',
        ],
        "recommendation": "Validate and sanitize file paths. Use os.path.basename() and restrict to allowed directories."
    },
    {
        "category": "Insecure Deserialization",
        "severity": "CRITICAL",
        "patterns": [
            r'pickle\.loads\s*\(',
            r'pickle\.load\s*\(',
            r'yaml\.load\s*\([^,)]*\)',      # yaml.load without Loader=
            r'marshal\.loads\s*\(',
        ],
        "recommendation": "Avoid pickle for untrusted data. Use yaml.safe_load() instead of yaml.load()."
    },
    {
        "category": "Weak Cryptography",
        "severity": "HIGH",
        "patterns": [
            r'hashlib\.md5\s*\(',
            r'hashlib\.sha1\s*\(',
            r'DES\s*\(',
            r'RC4\s*\(',
            r'random\.\w+\(\)',              # using random for security purposes
        ],
        "recommendation": "Use strong algorithms: SHA-256+, AES-256, bcrypt for passwords."
    },
    {
        "category": "Command Injection",
        "severity": "CRITICAL",
        "patterns": [
            r'os\.system\s*\(\s*\w*\s*\+',
            r'os\.system\s*\(\s*f["\']',
            r'subprocess\.\w+\s*\(\s*\w*\s*\+',
            r'shell=True',
        ],
        "recommendation": "Never pass user input to shell commands. Use subprocess with a list of arguments and shell=False."
    },
    {
        "category": "Debug Code in Production",
        "severity": "MEDIUM",
        "patterns": [
            r'debug\s*=\s*True',
            r'app\.run\s*\(.*?debug\s*=\s*True',
            r'console\.log\s*\(.*?password',
            r'print\s*\(.*?password',
            r'print\s*\(.*?secret',
            r'print\s*\(.*?token',
        ],
        "recommendation": "Remove debug flags and logs that expose sensitive data before deploying."
    },
]


def scan_file_for_security_issues(filename: str, patch: str) -> List[SecurityIssue]:
    """Scan a file's diff patch for security vulnerabilities."""
    issues = []
    
    if not patch:
        return issues
    
    # Only scan added lines (lines starting with +) not removed ones
    lines = patch.split("\n")
    line_number = 0
    
    for line in lines:
        # Track line numbers from diff headers like @@ -10,7 +10,7 @@
        if line.startswith("@@"):
            try:
                # Extract the starting line number for added lines
                match = re.search(r'\+(\d+)', line)
                if match:
                    line_number = int(match.group(1)) - 1
            except:
                pass
            continue
        
        if line.startswith("+") and not line.startswith("+++"):
            line_number += 1
            actual_line = line[1:]  # Remove the + prefix
            
            for rule in SECURITY_PATTERNS:
                for pattern in rule["patterns"]:
                    if re.search(pattern, actual_line, re.IGNORECASE):
                        issues.append(SecurityIssue(
                            severity=rule["severity"],
                            category=rule["category"],
                            line_number=line_number,
                            line_content=actual_line.strip(),
                            description=f"Potential {rule['category']} vulnerability detected.",
                            recommendation=rule["recommendation"]
                        ))
                        break  # One match per rule per line is enough
        
        elif not line.startswith("-"):
            line_number += 1
    
    return issues


def format_security_issues_for_ai(issues: List[SecurityIssue]) -> str:
    """Format detected issues into a string the AI can use as context."""
    if not issues:
        return "No obvious security vulnerabilities detected by static analysis."
    
    formatted = "## Static Security Analysis Found:\n\n"
    for issue in issues:
        formatted += f"- **[{issue.severity}] {issue.category}** at line {issue.line_number}\n"
        formatted += f"  Code: `{issue.line_content[:100]}`\n"
        formatted += f"  Fix: {issue.recommendation}\n\n"
    
    return formatted