import Navbar from "@/components/Navbar";
import Hero from "@/components/Hero";
import Features from "@/components/Features";
import Reviews from "@/components/Reviews";
import CTA from "@/components/CTA";
import Footer from "@/components/Footer";

export default function LandingPage() {
  const apiUrl = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";
  return (
    <main style={{ background: "#fff" }}>
      <Navbar apiUrl={apiUrl} />
      <Hero apiUrl={apiUrl} />
      <Features />
      
      <Reviews />
      <CTA apiUrl={apiUrl} />
      <Footer />
    </main>
  );
}