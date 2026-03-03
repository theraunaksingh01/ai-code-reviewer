export default function Architecture() {
  return (
    <section id="architecture" className="py-20 bg-gray-950 text-white px-6">
      <div className="max-w-5xl mx-auto text-center">
        <h2 className="text-3xl md:text-4xl font-bold mb-8">
          System Architecture
        </h2>

        <div className="bg-black border border-gray-800 p-8 rounded-xl text-gray-400">
          GitHub Webhook → FastAPI Server → Async Queue → 
          Static Security Engine → RAG Retrieval → 
          LLM Review Engine → GitHub Inline Comments → 
          Risk Score Calculation
        </div>
      </div>
    </section>
  );
}