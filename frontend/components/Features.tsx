"use client";
import { motion, useInView } from "framer-motion";
import { useRef } from "react";

const features = [
  {
    title: "Advanced Dashboard",
    desc: "Track PR quality scores, security trends, and developer performance across all your repos.",
    visual: (
      <div style={{ padding: "20px 16px 0" }}>
        <div style={{ background: "#fff", borderRadius: 12, border: "1px solid #efefef", padding: 14, boxShadow: "0 2px 12px rgba(0,0,0,0.04)" }}>
          <div style={{ display: "flex", gap: 8, marginBottom: 12 }}>
            {["User Detail","Performance","Sales Metrics","Issue Metrics"].map((t) => (
              <span key={t} style={{ fontSize: 9, color: "#aaa", fontFamily: "'DM Sans',sans-serif", background: "#f5f5f5", padding: "2px 6px", borderRadius: 4 }}>{t}</span>
            ))}
          </div>
          {[80, 55, 40, 65].map((w, i) => (
            <div key={i} style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6 }}>
              <div style={{ fontSize: 9, color: "#ccc", width: 24, fontFamily: "'DM Sans',sans-serif" }}>{["80%","55%","40%","65%"][i]}</div>
              <div style={{ flex: 1, height: 8, background: "#f5f5f5", borderRadius: 100 }}>
                <div style={{ width: `${w}%`, height: "100%", background: ["#6366f1","#f59e0b","#ef4444","#22c55e"][i], borderRadius: 100 }} />
              </div>
            </div>
          ))}
        </div>
        <div style={{ background: "#fff", borderRadius: 10, padding: "8px 14px", marginTop: 8, display: "inline-block", boxShadow: "0 2px 8px rgba(0,0,0,0.06)", border: "1px solid #efefef" }}>
          <span style={{ fontFamily: "'DM Sans',sans-serif", fontSize: 11, fontWeight: 600, color: "#0a0a0a" }}>Advance Dashboard</span>
        </div>
      </div>
    ),
  },
  {
    title: "Security Scanner",
    desc: "Automatically detects SQL injection, exposed API keys, XSS, command injection, and more.",
    visual: (
      <div style={{ padding: "20px 16px 0", display: "flex", flexDirection: "column" as const, alignItems: "center", gap: 10 }}>
        <div style={{ display: "flex", gap: 8 }}>
          {["SQL Injection","XSS","CSRF","Secrets"].map((t) => (
            <span key={t} style={{ background: "#fff", border: "1px solid #efefef", borderRadius: 8, padding: "6px 10px", fontSize: 10, fontWeight: 600, fontFamily: "'DM Sans',sans-serif", color: "#0a0a0a", boxShadow: "0 1px 4px rgba(0,0,0,0.05)" }}>{t}</span>
          ))}
        </div>
        <div style={{ background: "#fff", border: "1px solid #efefef", borderRadius: 12, padding: 14, width: "80%", boxShadow: "0 2px 12px rgba(0,0,0,0.04)" }}>
          <div style={{ height: 8, background: "#f5f5f5", borderRadius: 4, marginBottom: 6 }} />
          <div style={{ display: "flex", gap: 8, marginBottom: 8 }}>
            {["★★★★","★★★★","★★★★","★★★★"].map((s, i) => (
              <span key={i} style={{ fontSize: 10, color: "#f59e0b" }}>{s}</span>
            ))}
          </div>
          <div style={{ height: 32, background: "#ef4444", borderRadius: 8 }} />
        </div>
      </div>
    ),
  },
  {
    title: "Easy Export",
    desc: "Export review reports as plain text, PDF, Word or HTML. Share findings with your team instantly.",
    visual: (
      <div style={{ padding: "20px 16px 0", display: "flex", flexDirection: "column" as const, alignItems: "flex-end", gap: 10 }}>
        <div style={{ display: "flex", gap: 8 }}>
          {["PDF","TXT","Doc","HTML"].map((t) => (
            <span key={t} style={{ background: "#fff", border: "1px solid #efefef", borderRadius: 8, padding: "6px 12px", fontSize: 11, fontWeight: 700, fontFamily: "'DM Sans',sans-serif", color: "#0a0a0a", boxShadow: "0 1px 4px rgba(0,0,0,0.05)" }}>{t}</span>
          ))}
        </div>
        <div style={{ background: "#fff", border: "1px solid #efefef", borderRadius: 12, padding: 14, width: "85%", boxShadow: "0 2px 12px rgba(0,0,0,0.04)" }}>
          {[100, 80, 90, 60, 70].map((w, i) => (
            <div key={i} style={{ height: 8, background: "#f5f5f5", borderRadius: 4, marginBottom: 6, width: `${w}%` }} />
          ))}
          <div style={{ height: 4, background: "#f59e0b", borderRadius: 4, marginTop: 8 }} />
        </div>
      </div>
    ),
  },
  {
    title: "Multi-Repo Support",
    desc: "Connect all your GitHub repos and get unified security intelligence across your entire organization.",
    visual: (
      <div style={{ padding: "20px 16px 0", display: "flex", alignItems: "center", justifyContent: "center" }}>
        <div style={{ position: "relative", width: 120, height: 120 }}>
          <div style={{ position: "absolute", inset: 0, borderRadius: "50%", border: "1.5px dashed #ddd", display: "flex", alignItems: "center", justifyContent: "center" }}>
            <div style={{ width: 44, height: 44, borderRadius: "50%", background: "#fff", border: "1px solid #efefef", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 20, boxShadow: "0 2px 8px rgba(0,0,0,0.06)" }}>🛡️</div>
          </div>
          {[{top:-8,left:"50%",t:"-8px",l:"50%",emoji:"⚛️"},{top:"50%",right:-8,emoji:"🐍"},{bottom:-8,left:"50%",emoji:"🦫"},{top:"50%",left:-8,emoji:"☕"}].map((pos, i) => (
            <div key={i} style={{
              position: "absolute", ...pos as any,
              width: 28, height: 28, borderRadius: "50%",
              background: "#fff", border: "1px solid #efefef",
              display: "flex", alignItems: "center", justifyContent: "center",
              fontSize: 13, boxShadow: "0 2px 6px rgba(0,0,0,0.06)",
              transform: "translate(-50%,-50%)",
            }}>{pos.emoji}</div>
          ))}
        </div>
      </div>
    ),
  },
  {
    title: "Developer Scorecards",
    desc: "Each developer gets a personal scorecard showing quality trends, recurring issues, and improvement over time.",
    visual: (
      <div style={{ padding: "20px 16px 0", display: "flex", flexDirection: "column" as const, alignItems: "center" }}>
        <div style={{ display: "flex", alignItems: "center", marginBottom: 10 }}>
          {["#6366f1","#8b5cf6","#ec4899","#f59e0b","#22c55e"].map((c, i) => (
            <div key={i} style={{
              width: 36, height: 36, borderRadius: "50%",
              border: "2.5px solid #f0eeea", marginLeft: i === 0 ? 0 : -8,
              background: c, display: "flex", alignItems: "center", justifyContent: "center",
              fontSize: 12, color: "#fff", fontWeight: 700, fontFamily: "'DM Sans',sans-serif",
            }}>{["R","A","S","T","M"][i]}</div>
          ))}
        </div>
        <div style={{ background: "#fff", border: "1px solid #efefef", borderRadius: 16, padding: "12px 20px", textAlign: "center" as const, boxShadow: "0 2px 12px rgba(0,0,0,0.06)" }}>
          <div style={{ fontSize: 11, color: "#aaa", fontFamily: "'DM Sans',sans-serif", marginBottom: 2 }}>Team Avg Score</div>
          <div style={{ fontFamily: "'Syne',sans-serif", fontSize: 24, fontWeight: 800, color: "#22c55e" }}>84/100</div>
        </div>
        <button style={{ marginTop: 10, background: "transparent", border: "1px solid #e0e0e0", borderRadius: 100, padding: "6px 16px", fontSize: 12, cursor: "pointer", fontFamily: "'DM Sans',sans-serif", color: "#666" }}>+ Invite Developer</button>
      </div>
    ),
  },
  {
    title: "Slack Integration",
    desc: "Critical security vulnerabilities get blasted to your team's Slack or Discord channel instantly.",
    visual: (
      <div style={{ padding: "20px 16px 0" }}>
        <div style={{ background: "#fff", border: "1px solid #efefef", borderRadius: 12, padding: 14, boxShadow: "0 2px 12px rgba(0,0,0,0.04)" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 10 }}>
            <div style={{ width: 10, height: 10, borderRadius: "50%", background: "#22c55e" }} />
            <span style={{ fontFamily: "'DM Sans',sans-serif", fontSize: 12, fontWeight: 600, color: "#0a0a0a" }}>Slack Notifications</span>
          </div>
          {["🔴 CRITICAL: SQL Injection in PR #23","🟡 HIGH: Exposed secret in PR #24","✅ PR #25 passed all checks"].map((msg, i) => (
            <div key={i} style={{ fontSize: 11, color: "#666", fontFamily: "'DM Sans',sans-serif", padding: "5px 8px", background: "#f9f9f9", borderRadius: 6, marginBottom: 5 }}>{msg}</div>
          ))}
          <button style={{ marginTop: 6, width: "100%", background: "transparent", border: "1.5px dashed #ddd", borderRadius: 8, padding: "7px", fontSize: 12, cursor: "pointer", fontFamily: "'DM Sans',sans-serif", color: "#aaa" }}>+ Add comment</button>
        </div>
      </div>
    ),
  },
];

function Card({ feature, index }: { feature: typeof features[0]; index: number }) {
  const ref = useRef(null);
  const inView = useInView(ref, { once: true, margin: "-60px" });

  return (
    <motion.div
      ref={ref}
      initial={{ opacity: 0, y: 48 }}
      animate={inView ? { opacity: 1, y: 0 } : {}}
      transition={{ duration: 0.7, ease: [0.22, 1, 0.36, 1], delay: (index % 3) * 0.1 }}
      whileHover={{ y: -4, boxShadow: "0 16px 48px rgba(0,0,0,0.09)" }}
      style={{
        background: "#fff", border: "1px solid #efefef",
        borderRadius: 20, overflow: "hidden",
        display: "flex", flexDirection: "column",
        cursor: "default", transition: "box-shadow 0.25s",
      }}
    >
      <div style={{ height: 200, background: "#fafafa", borderBottom: "1px solid #f5f5f5", overflow: "hidden" }}>
        {feature.visual}
      </div>
      <div style={{ padding: "20px 24px 24px" }}>
        <div style={{ fontFamily: "'Syne',sans-serif", fontSize: 16, fontWeight: 700, color: "#0a0a0a", marginBottom: 8 }}>{feature.title}</div>
        <div style={{ fontFamily: "'DM Sans',sans-serif", fontSize: 13, color: "#999", lineHeight: 1.7, fontWeight: 300 }}>{feature.desc}</div>
      </div>
    </motion.div>
  );
}

export default function Features() {
  const headerRef = useRef(null);
  const headerInView = useInView(headerRef, { once: true, margin: "-60px" });

  return (
    <section id="features" style={{ background: "#f5f3ef", padding: "100px 28px" }}>
      <div style={{ maxWidth: 1100, margin: "0 auto" }}>
        <motion.div
          ref={headerRef}
          initial={{ opacity: 0, y: 32 }}
          animate={headerInView ? { opacity: 1, y: 0 } : {}}
          transition={{ duration: 0.7, ease: [0.22, 1, 0.36, 1] }}
          style={{ textAlign: "center", marginBottom: 60 }}
        >
          <span style={{
            display: "inline-flex", alignItems: "center", gap: 6,
            background: "#fff", border: "1px solid #e8e4df", borderRadius: 100,
            padding: "5px 14px", fontSize: 12, fontWeight: 600,
            letterSpacing: "0.06em", textTransform: "uppercase" as const,
            color: "#888", marginBottom: 20, fontFamily: "'DM Sans',sans-serif",
            boxShadow: "0 2px 6px rgba(0,0,0,0.04)",
          }}>
            🛠️ Features
          </span>
          <h2 style={{
            fontFamily: "'Syne',sans-serif",
            fontSize: "clamp(36px, 5vw, 56px)", fontWeight: 800,
            lineHeight: 1.08, letterSpacing: "-0.03em",
            color: "#0a0a0a", marginBottom: 16,
          }}>Magic Tools</h2>
          <p style={{
            fontFamily: "'DM Sans',sans-serif", fontSize: 16, color: "#888",
            maxWidth: 480, margin: "0 auto", lineHeight: 1.7, fontWeight: 300,
          }}>
            CodeSentinel has all the tools you need to ship secure, high-quality code automatically.
          </p>
        </motion.div>

        <div style={{
          display: "grid",
          gridTemplateColumns: "repeat(3, 1fr)",
          gap: 16,
        }}>
          {features.map((f, i) => <Card key={f.title} feature={f} index={i} />)}
        </div>
      </div>

      <style>{`
        @media (max-width: 900px) {
          #features > div > div:last-child { grid-template-columns: repeat(2,1fr) !important; }
        }
        @media (max-width: 580px) {
          #features > div > div:last-child { grid-template-columns: 1fr !important; }
        }
      `}</style>
    </section>
  );
}