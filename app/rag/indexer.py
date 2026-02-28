import os
import chromadb
from sentence_transformers import SentenceTransformer
from github import GithubIntegration, Github
from dotenv import load_dotenv

load_dotenv()

APP_ID = os.getenv("GITHUB_APP_ID")
PRIVATE_KEY_PATH = os.getenv("GITHUB_PRIVATE_KEY_PATH")

with open(PRIVATE_KEY_PATH, "r") as f:
    PRIVATE_KEY = f.read()

# Local ChromaDB stored in your project folder
chroma_client = chromadb.PersistentClient(path="./chroma_db")
collection = chroma_client.get_or_create_collection(name="pr_history")

# Free local embedding model — no API key needed
embedder = SentenceTransformer("all-MiniLM-L6-v2")


def get_github_client(repo_name: str):
    integration = GithubIntegration(APP_ID, PRIVATE_KEY)
    owner = repo_name.split("/")[0]
    installation = integration.get_installation(owner, repo_name.split("/")[1])
    access_token = integration.get_access_token(installation.id).token
    return Github(access_token)


def index_merged_prs(repo_name: str, max_prs: int = 20):
    """Fetch merged PRs and store them in ChromaDB."""
    print(f"📚 Indexing merged PRs from {repo_name}...")

    client = get_github_client(repo_name)
    repo = client.get_repo(repo_name)

    merged_prs = []
    for pr in repo.get_pulls(state="closed", sort="updated", direction="desc"):
        if pr.merged and len(merged_prs) < max_prs:
            merged_prs.append(pr)

    if not merged_prs:
        print("No merged PRs found — skipping indexing")
        return

    documents = []
    metadatas = []
    ids = []

    for pr in merged_prs:
        for file in pr.get_files():
            if not file.patch:
                continue

            # Create a meaningful text chunk for each file in each PR
            chunk = f"""
PR Title: {pr.title}
File: {file.filename}
Changes:
{file.patch[:1000]}
"""
            doc_id = f"pr_{pr.number}_file_{file.filename.replace('/', '_')}"

            # Skip if already indexed
            existing = collection.get(ids=[doc_id])
            if existing["ids"]:
                continue

            documents.append(chunk)
            metadatas.append({
                "pr_number": pr.number,
                "pr_title": pr.title,
                "filename": file.filename,
                "repo": repo_name
            })
            ids.append(doc_id)

    if not documents:
        print("All PRs already indexed")
        return

    # Convert to embeddings and store
    embeddings = embedder.encode(documents).tolist()
    collection.add(
        documents=documents,
        embeddings=embeddings,
        metadatas=metadatas,
        ids=ids
    )

    print(f"✅ Indexed {len(documents)} file chunks from {len(merged_prs)} merged PRs")


def index_single_merged_pr(repo_name: str, pr_number: int):
    """Index a single PR after it gets merged — called automatically."""
    client = get_github_client(repo_name)
    repo = client.get_repo(repo_name)
    pr = repo.get_pull(pr_number)

    if not pr.merged:
        return

    documents = []
    metadatas = []
    ids = []

    for file in pr.get_files():
        if not file.patch:
            continue

        chunk = f"""
PR Title: {pr.title}
File: {file.filename}
Changes:
{file.patch[:1000]}
"""
        doc_id = f"pr_{pr.number}_file_{file.filename.replace('/', '_')}"

        documents.append(chunk)
        metadatas.append({
            "pr_number": pr.number,
            "pr_title": pr.title,
            "filename": file.filename,
            "repo": repo_name
        })
        ids.append(doc_id)

    if documents:
        embeddings = embedder.encode(documents).tolist()
        collection.add(
            documents=documents,
            embeddings=embeddings,
            metadatas=metadatas,
            ids=ids
        )
        print(f"✅ Auto-indexed merged PR #{pr_number}")