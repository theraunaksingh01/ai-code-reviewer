import chromadb
from sentence_transformers import SentenceTransformer

chroma_client = chromadb.PersistentClient(path="./chroma_db")
collection = chroma_client.get_or_create_collection(name="pr_history")

embedder = SentenceTransformer("all-MiniLM-L6-v2")


def get_relevant_context(query: str, n_results: int = 3) -> str:
    """Find similar past PR patterns relevant to current code being reviewed."""

    # Check if collection has any documents
    if collection.count() == 0:
        return "No codebase history available yet — this appears to be an early PR."

    # Convert query to embedding and search
    query_embedding = embedder.encode([query]).tolist()

    results = collection.query(
        query_embeddings=query_embedding,
        n_results=min(n_results, collection.count())
    )

    if not results["documents"][0]:
        return "No similar patterns found in codebase history."

    # Format results for the AI prompt
    context = "## Relevant Codebase History:\n\n"
    for i, (doc, metadata) in enumerate(zip(
        results["documents"][0],
        results["metadatas"][0]
    )):
        context += f"**Similar pattern from PR #{metadata['pr_number']}**"
        context += f" — {metadata['pr_title']}\n"
        context += f"File: `{metadata['filename']}`\n"
        context += f"```\n{doc[:400]}\n```\n\n"

    return context
