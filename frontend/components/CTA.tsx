"use client";
import { motion, useInView } from "framer-motion";
import { useRef } from "react";

export default function CTA({ apiUrl }: { apiUrl: string }) {
  const ref = useRef(null);
  const inView = useInView(ref, { once: true, margin: "-80px" });

  return (
    <section style={{ padding: "0 28px 60px", background: "#fff" }}>
      <motion.div
        ref={ref}
        initial={{ opacity: 0, y: 40, scale: 0.98 }}
        animate={inView ? { opacity: 1, y: 0, scale: 1 } : { opacity: 0, y: 40, scale: 0.98 }}
        transition={{ duration: 0.8, ease: "easeOut" }}
        style={{
          maxWidth: 1100, margin: "0 auto",
          borderRadius: 24,
          background: "linear-gradient(135deg, #1a1a2e 0%, #16213e 40%, #0f3460 100%)",
          overflow: "hidden", position: "relative",
          minHeight: 300, display: "flex",
          alignItems: "center", padding: "60px 64px",
          gap: 60, flexWrap: "wrap" as const,
        }}
      >
        {/* Glows */}
        <div style={{ position: "absolute", top: -60, right: "30%", width: 300, height: 300, borderRadius: "50%", background: "radial-gradient(circle, rgba(99,102,241,0.3) 0%, transparent 70%)", pointerEvents: "none" }} />
        <div style={{ position: "absolute", bottom: -80, right: "10%", width: 400, height: 400, borderRadius: "50%", background: "radial-gradient(circle, rgba(34,211,153,0.12) 0%, transparent 70%)", pointerEvents: "none" }} />

        {/* Left text */}
        <div style={{ flex: 1, minWidth: 260, position: "relative", zIndex: 2 }}>
          <motion.h2
            initial={{ opacity: 0, y: 24 }}
            animate={inView ? { opacity: 1, y: 0 } : { opacity: 0, y: 24 }}
            transition={{ delay: 0.2, duration: 0.65, ease: "easeOut" }}
            style={{
              fontFamily: "'Syne',sans-serif",
              fontSize: "clamp(32px, 4vw, 52px)", fontWeight: 800,
              lineHeight: 1.05, letterSpacing: "-0.03em",
              color: "#fff", marginBottom: 16,
            }}
          >
            Review without<br />limit
          </motion.h2>
          <motion.p
            initial={{ opacity: 0, y: 16 }}
            animate={inView ? { opacity: 1, y: 0 } : { opacity: 0, y: 16 }}
            transition={{ delay: 0.3, duration: 0.6, ease: "easeOut" }}
            style={{
              fontFamily: "'DM Sans',sans-serif", fontSize: 16,
              color: "rgba(255,255,255,0.55)", lineHeight: 1.65,
              maxWidth: 360, fontWeight: 300,
            }}
          >
            Connect GitHub and get AI-powered security reviews on every pull request. Easy to set up in minutes.
          </motion.p>
        </div>

        {/* Right widget — Livevisa-style */}
        <motion.div
          initial={{ opacity: 0, x: 40 }}
          animate={inView ? { opacity: 1, x: 0 } : { opacity: 0, x: 40 }}
          transition={{ delay: 0.4, duration: 0.7, ease: "easeOut" }}
          style={{
            background: "rgba(255,255,255,0.07)", backdropFilter: "blur(20px)",
            border: "1px solid rgba(255,255,255,0.12)",
            borderRadius: 20, padding: 24, width: 340,
            position: "relative", zIndex: 2, flexShrink: 0,
          }}
        >
          <div style={{ marginBottom: 14 }}>
            <div style={{ fontFamily: "'DM Sans',sans-serif", fontSize: 12, color: "rgba(255,255,255,0.38)", marginBottom: 8, display: "flex", alignItems: "center", gap: 6 }}>
              <span>🔗</span> Your GitHub
            </div>
            <div style={{
              background: "rgba(255,255,255,0.07)", border: "1px solid rgba(255,255,255,0.1)",
              borderRadius: 12, padding: "12px 16px",
              fontFamily: "'DM Sans',sans-serif", fontSize: 14,
              color: "rgba(255,255,255,0.28)",
              display: "flex", alignItems: "center", justifyContent: "space-between",
            }}>
              <span>Enter your repository...</span>
              <svg width="14" height="14" viewBox="0 0 14 14" fill="none">
                <path d="M3 5l4 4 4-4" stroke="rgba(255,255,255,0.4)" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
              </svg>
            </div>
          </div>
          <a
            href={`${apiUrl}/api/auth/login`}
            style={{
              display: "flex", alignItems: "center", justifyContent: "center",
              background: "#fff", color: "#0a0a0a",
              border: "none", borderRadius: 12,
              padding: "13px 20px", fontSize: 14, fontWeight: 600,
              cursor: "pointer", textDecoration: "none",
              fontFamily: "'DM Sans',sans-serif", gap: 8,
              transition: "background 0.2s",
              width: "100%", boxSizing: "border-box" as const,
            }}
            onMouseEnter={(e) => (e.currentTarget.style.background = "#f0f0f0")}
            onMouseLeave={(e) => (e.currentTarget.style.background = "#fff")}
          >
            <svg width="15" height="15" viewBox="0 0 15 15" fill="none">
              <circle cx="9" cy="6" r="5" stroke="#0a0a0a" strokeWidth="1.5"/>
              <line x1="5.5" y1="10" x2="1" y2="14.5" stroke="#0a0a0a" strokeWidth="1.5" strokeLinecap="round"/>
            </svg>
            Start Reviewing Free
          </a>
        </motion.div>
      </motion.div>
    </section>
  );
}