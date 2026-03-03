"use client";
import { motion, useInView } from "framer-motion";
import { useRef } from "react";

const footerLinks: Record<string, string[]> = {
  Products:  ["Get the app", "API Access", "Integrations", "Changelog"],
  Company:   ["About", "Careers", "Press", "Get in touch"],
  Resources: ["Documentation", "Support", "Blog", "Tutorials"],
  Partner:   ["For startups", "For enterprise", "For agencies", "For experts"],
  Explore:   ["Compare", "Community", "Roadmap", "Wishlist"],
};

export default function Footer() {
  const ref = useRef(null);
  const inView = useInView(ref, { once: true, margin: "-40px" });

  return (
    <>
      <motion.footer
        ref={ref}
        initial={{ opacity: 0, y: 24 }}
        animate={inView ? { opacity: 1, y: 0 } : { opacity: 0, y: 24 }}
        transition={{ duration: 0.6, ease: "easeOut" }}
        style={{ background: "#fff", borderTop: "1px solid #f0f0f0", padding: "60px 28px 0" }}
      >
        <div style={{ maxWidth: 1100, margin: "0 auto" }}>

          {/* Top grid */}
          <div
            className="footer-grid"
            style={{
              display: "grid",
              gridTemplateColumns: "1.4fr repeat(5, 1fr)",
              gap: 40,
              paddingBottom: 48,
              borderBottom: "1px solid #f0f0f0",
            }}
          >
            {/* Brand col */}
            <div>
              <a href="/" style={{ display: "flex", alignItems: "center", gap: 8, textDecoration: "none", color: "#0a0a0a", marginBottom: 14 }}>
                <div style={{ width: 32, height: 32, background: "#0a0a0a", borderRadius: 8, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 15 }}>🛡️</div>
                <span style={{ fontFamily: "'Syne',sans-serif", fontSize: 16, fontWeight: 700, letterSpacing: "-0.02em" }}>CodeSentinel</span>
              </a>
              <p style={{ fontFamily: "'DM Sans',sans-serif", fontSize: 13, color: "#aaa", lineHeight: 1.7, fontWeight: 300, maxWidth: 210 }}>
                <strong style={{ color: "#0a0a0a", fontWeight: 600 }}>CodeSentinel</strong> is the world&apos;s leading AI code review platform for engineering teams.
              </p>
            </div>

            {/* Link columns */}
            {Object.entries(footerLinks).map(([col, items]) => (
              <div key={col}>
                <div style={{ fontFamily: "'DM Sans',sans-serif", fontSize: 11, fontWeight: 700, letterSpacing: "0.08em", textTransform: "uppercase" as const, color: "#aaa", marginBottom: 16 }}>{col}</div>
                <ul style={{ listStyle: "none", padding: 0, margin: 0 }}>
                  {items.map((l) => (
                    <li key={l} style={{ marginBottom: 10 }}>
                      <a
                        href="#"
                        style={{ fontFamily: "'DM Sans',sans-serif", fontSize: 13, color: "#555", textDecoration: "none", transition: "color 0.2s" }}
                        onMouseEnter={(e) => (e.currentTarget.style.color = "#0a0a0a")}
                        onMouseLeave={(e) => (e.currentTarget.style.color = "#555")}
                      >{l}</a>
                    </li>
                  ))}
                </ul>
              </div>
            ))}
          </div>

          {/* Bottom bar */}
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "24px 0", flexWrap: "wrap" as const, gap: 12 }}>
            <span style={{ fontFamily: "'DM Sans',sans-serif", fontSize: 12, color: "#bbb" }}>
              Copyright © 2026 CodeSentinel Inc. All rights reserved.
            </span>
            <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
              <a href="#" style={{ fontFamily: "'DM Sans',sans-serif", fontSize: 12, color: "#bbb", textDecoration: "underline", textUnderlineOffset: 3, transition: "color 0.2s" }}
                onMouseEnter={(e) => (e.currentTarget.style.color = "#555")}
                onMouseLeave={(e) => (e.currentTarget.style.color = "#bbb")}
              >Privacy Policy</a>
              <span style={{ color: "#ddd", fontSize: 12 }}>&amp;</span>
              <a href="#" style={{ fontFamily: "'DM Sans',sans-serif", fontSize: 12, color: "#bbb", textDecoration: "underline", textUnderlineOffset: 3, transition: "color 0.2s" }}
                onMouseEnter={(e) => (e.currentTarget.style.color = "#555")}
                onMouseLeave={(e) => (e.currentTarget.style.color = "#bbb")}
              >Terms of Use</a>
            </div>
          </div>
        </div>
      </motion.footer>

      {/* Watermark */}
      <div style={{
        fontFamily: "'Syne',sans-serif",
        fontSize: "clamp(52px, 10vw, 128px)", fontWeight: 800,
        letterSpacing: "-0.05em", color: "#f3f3f3",
        textAlign: "center", lineHeight: 1,
        padding: "0 28px 28px",
        pointerEvents: "none", userSelect: "none",
        overflow: "hidden", background: "#fff",
      }}>
        CodeSentinel
      </div>

      <style>{`
        @media (max-width: 960px) { .footer-grid { grid-template-columns: 1fr 1fr 1fr !important; } }
        @media (max-width: 580px) { .footer-grid { grid-template-columns: 1fr 1fr !important; } }
        @media (max-width: 380px) { .footer-grid { grid-template-columns: 1fr !important; } }
      `}</style>
    </>
  );
}