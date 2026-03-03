"use client";
import { useRef } from "react";
import { motion, useInView } from "framer-motion";

type Review = {
  type: "text" | "featured" | "photo";
  name: string;
  role: string;
  quote?: string;
  gradient?: string;
};

const col1: Review[] = [
  {
    type: "text",
    quote: "CodeSentinel caught a critical SQL injection in our PR before it went live. It felt like having a senior security engineer on every review.",
    name: "Priya Sharma",
    role: "Lead Engineer @ Stripe",
  },
  {
    type: "photo",
    name: "B.A. Baracus",
    role: "VP of Design @ BuildCo",
    gradient: "linear-gradient(160deg, #1a3a2e 0%, #0d2b1e 100%)",
  },
];

const col2: Review[] = [
  {
    type: "featured",
    name: "Marcus Chen",
    role: "CTO @ DevFlow",
    quote: "The RAG feature is what blew us away — it actually understood our codebase conventions and flagged deviations. No other tool does that.",
  },
  {
    type: "text",
    quote: "CodeSentinel delivered far beyond our expectations. It automatically opened fix PRs for the issues it found — that alone saved us hours every week.",
    name: "Danny Tanner",
    role: "Co-Founder & CTO @ Launchpad",
  },
];

const col3: Review[] = [
  {
    type: "text",
    quote: "We connected our repos in 5 minutes and got our first review in under a minute. The developer scorecards have made our code quality conversations data-driven.",
    name: "Lynn Torres",
    role: "VP Engineering @ Acme",
  },
  {
    type: "photo",
    name: "Hannibal Smith",
    role: "Creative Director",
    gradient: "linear-gradient(160deg, #1a2030 0%, #0d1520 100%)",
  },
];

function Avatar({ name, color = "#6366f1" }: { name: string; color?: string }) {
  return (
    <div style={{
      width: 36, height: 36, borderRadius: "50%", background: color,
      display: "flex", alignItems: "center", justifyContent: "center",
      fontSize: 14, fontWeight: 700, color: "#fff",
      fontFamily: "'Instrument Sans', sans-serif", flexShrink: 0,
    }}>
      {name[0]}
    </div>
  );
}

function PlayButton() {
  return (
    <div style={{
      width: 38, height: 38, borderRadius: "50%",
      background: "rgba(255,255,255,0.2)", backdropFilter: "blur(12px)",
      border: "1px solid rgba(255,255,255,0.3)",
      display: "flex", alignItems: "center", justifyContent: "center",
      cursor: "pointer",
      transition: "background 0.2s, transform 0.2s",
    }}
    onMouseEnter={(e) => { (e.currentTarget as HTMLDivElement).style.background = "rgba(255,255,255,0.35)"; (e.currentTarget as HTMLDivElement).style.transform = "scale(1.08)"; }}
    onMouseLeave={(e) => { (e.currentTarget as HTMLDivElement).style.background = "rgba(255,255,255,0.2)"; (e.currentTarget as HTMLDivElement).style.transform = "scale(1)"; }}
    >
      <svg width="12" height="14" viewBox="0 0 12 14" fill="white">
        <path d="M1 1.5l10 5-10 5V1.5z" />
      </svg>
    </div>
  );
}

function ReviewCard({ review, delay }: { review: Review; delay: number }) {
  const ref = useRef(null);
  const inView = useInView(ref, { once: true, margin: "-50px" });

  /* ── PHOTO card ── */
  if (review.type === "photo") {
    return (
      <motion.div
        ref={ref}
        initial={{ opacity: 0, y: 36 }}
        animate={inView ? { opacity: 1, y: 0 } : {}}
        transition={{ duration: 0.7, ease: "easeOut", delay }}
        whileHover={{ y: -4, transition: { duration: 0.25 } }}
        style={{
          borderRadius: 20, overflow: "hidden",
          background: review.gradient,
          minHeight: 220, position: "relative",
          display: "flex", alignItems: "flex-end",
          padding: "20px 22px",
          cursor: "pointer",
        }}
      >
        {/* Noise overlay */}
        <div style={{
          position: "absolute", inset: 0,
          background: "url(\"data:image/svg+xml,%3Csvg viewBox='0 0 200 200' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.75' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)' opacity='0.04'/%3E%3C/svg%3E\")",
          opacity: 0.6, pointerEvents: "none",
        }} />
        <div style={{ position: "relative", zIndex: 1, flex: 1 }}>
          <div style={{ fontFamily: "'Instrument Sans', sans-serif", fontSize: 15, fontWeight: 700, color: "#fff", marginBottom: 3 }}>{review.name}</div>
          <div style={{ fontFamily: "'Instrument Sans', sans-serif", fontSize: 12, color: "rgba(255,255,255,0.5)" }}>{review.role}</div>
        </div>
        <div style={{ position: "absolute", top: 20, right: 20, zIndex: 1 }}>
          <PlayButton />
        </div>
      </motion.div>
    );
  }

  /* ── FEATURED card (dark with quote) ── */
  if (review.type === "featured") {
    return (
      <motion.div
        ref={ref}
        initial={{ opacity: 0, y: 36 }}
        animate={inView ? { opacity: 1, y: 0 } : {}}
        transition={{ duration: 0.7, ease: "easeOut", delay }}
        whileHover={{ y: -4, transition: { duration: 0.25 } }}
        style={{
          borderRadius: 20, overflow: "hidden",
          background: "linear-gradient(160deg, #1a2235 0%, #111827 100%)",
          padding: "26px 26px 24px",
          position: "relative",
          cursor: "pointer",
        }}
      >
        {/* Top row: name + play */}
        <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", marginBottom: 20 }}>
          <div>
            <div style={{ fontFamily: "'Instrument Sans', sans-serif", fontSize: 15, fontWeight: 700, color: "#fff", marginBottom: 3 }}>{review.name}</div>
            <div style={{ fontFamily: "'Instrument Sans', sans-serif", fontSize: 12, color: "#22c55e" }}>{review.role}</div>
          </div>
          <PlayButton />
        </div>
        <p style={{
          fontFamily: "'Instrument Sans', sans-serif",
          fontSize: 15, color: "rgba(255,255,255,0.75)",
          lineHeight: 1.75, fontWeight: 400,
        }}>
          &ldquo;{review.quote}&rdquo;
        </p>
      </motion.div>
    );
  }

  /* ── TEXT card ── */
  return (
    <motion.div
      ref={ref}
      initial={{ opacity: 0, y: 36 }}
      animate={inView ? { opacity: 1, y: 0 } : {}}
      transition={{ duration: 0.7, ease: "easeOut", delay }}
      whileHover={{ y: -4, boxShadow: "0 16px 40px rgba(0,0,0,0.07)", transition: { duration: 0.25 } }}
      style={{
        background: "#fff", border: "1px solid #eeeae6",
        borderRadius: 20, padding: "24px 26px",
        boxShadow: "0 2px 12px rgba(0,0,0,0.04)",
      }}
    >
      <p style={{
        fontFamily: "'Instrument Sans', sans-serif",
        fontSize: 14, color: "#333",
        lineHeight: 1.8, fontWeight: 400, marginBottom: 22,
      }}>
        &ldquo;{review.quote}&rdquo;
      </p>
      <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
        <Avatar name={review.name} color={["Priya","Lynn","Kevin"].includes(review.name.split(" ")[0]) ? "#6366f1" : "#8b5cf6"} />
        <div>
          <div style={{ fontFamily: "'Instrument Sans', sans-serif", fontSize: 13, fontWeight: 700, color: "#0a0a0a" }}>{review.name}</div>
          <div style={{ fontFamily: "'Instrument Sans', sans-serif", fontSize: 12, color: "#aaa" }}>{review.role}</div>
        </div>
      </div>
    </motion.div>
  );
}

export default function Reviews() {
  const headerRef = useRef(null);
  const inView = useInView(headerRef, { once: true, margin: "-60px" });

  return (
    <>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Bebas+Neue&family=Instrument+Sans:wght@400;500;600;700&display=swap');
        .reviews-masonry { display: grid; grid-template-columns: 1fr 1.22fr 1fr; gap: 16px; align-items: start; }
        @media (max-width: 900px) { .reviews-masonry { grid-template-columns: 1fr 1fr !important; } }
        @media (max-width: 600px) { .reviews-masonry { grid-template-columns: 1fr !important; } }
      `}</style>

      <section style={{ background: "#fff", padding: "100px 28px 80px" }}>
        <div style={{ maxWidth: 1120, margin: "0 auto" }}>

          {/* Header */}
          <div ref={headerRef} style={{ textAlign: "center", marginBottom: 64 }}>
            <motion.h2
              initial={{ opacity: 0, y: 40 }}
              animate={inView ? { opacity: 1, y: 0 } : {}}
              transition={{ duration: 0.8, ease: "easeOut" }}
              style={{
                fontFamily: "'Bebas Neue', sans-serif",
                fontSize: "clamp(44px, 7.5vw, 96px)",
                lineHeight: 1.0, letterSpacing: "0.01em",
                color: "#0a0a0a", marginBottom: 20,
              }}
            >
              Real People To Real Data<br />To Personalized Impact
            </motion.h2>
            <motion.p
              initial={{ opacity: 0, y: 20 }}
              animate={inView ? { opacity: 1, y: 0 } : {}}
              transition={{ duration: 0.6, ease: "easeOut", delay: 0.2 }}
              style={{
                fontFamily: "'Instrument Sans', sans-serif",
                fontSize: 16, color: "#888",
                maxWidth: 480, margin: "0 auto",
                lineHeight: 1.7, fontWeight: 400,
              }}
            >
              Hear from the engineers and teams who&apos;ve shipped more secure code using CodeSentinel.
            </motion.p>
          </div>

          {/* 3-column masonry */}
          <div className="reviews-masonry">
            {/* Col 1 */}
            <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
              {col1.map((r, i) => <ReviewCard key={r.name} review={r} delay={i * 0.08} />)}
            </div>
            {/* Col 2 */}
            <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
              {col2.map((r, i) => <ReviewCard key={r.name} review={r} delay={0.1 + i * 0.08} />)}
            </div>
            {/* Col 3 */}
            <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
              {col3.map((r, i) => <ReviewCard key={r.name} review={r} delay={0.05 + i * 0.08} />)}
            </div>
          </div>

        </div>
      </section>
    </>
  );
}