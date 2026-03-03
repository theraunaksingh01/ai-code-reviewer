export default function HowItWorks() {
  const steps = [
    "Developer opens Pull Request",
    "Webhook triggers AI review pipeline",
    "Static security rules scan diff",
    "RAG retrieves relevant code history",
    "LLM analyzes changes and assigns risk score",
    "Inline GitHub comments are posted"
  ];

  return (
    <section id="how" className="py-20 bg-black text-white px-6">
      <div className="max-w-6xl mx-auto text-center">
        <h2 className="text-3xl md:text-4xl font-bold mb-12">
          How It Works
        </h2>

        <div className="space-y-6 text-gray-400">
          {steps.map((step, index) => (
            <div key={index} className="text-lg">
              {index + 1}. {step}
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}