"use client";

import { useRef } from "react";
import { motion, useScroll, useTransform } from "framer-motion";

export default function Hero({ apiUrl }: { apiUrl: string }) {
  const containerRef = useRef<HTMLElement>(null);

  const { scrollYProgress } = useScroll({
    target: containerRef,
    offset: ["start start", "end start"],
  });

  const cardY = useTransform(scrollYProgress, [0, 1], ["0%", "8%"]);

  return (
    <section
      ref={containerRef}
      style={{
        background: "#ffffff",
        paddingTop: 110,
        overflow: "hidden",
      }}
    >
      {/* ================= TEXT BLOCK ================= */}
      <div
        style={{
          textAlign: "center",
          maxWidth: 950,
          margin: "0 auto",
          padding: "0 24px",
        }}
      >
        <div style={{ marginBottom: 32 }}>
          <span
            style={{
              display: "inline-flex",
              alignItems: "center",
              gap: 8,
              background: "#f4f4f5",
              border: "1px solid #e5e7eb",
              borderRadius: 999,
              padding: "8px 18px",
              fontSize: 13,
              fontWeight: 600,
              color: "#525252",
              fontFamily: "'Inter', system-ui, sans-serif",
            }}
          >
            🛡️ AI-Powered Code Intelligence Platform
          </span>
        </div>

        <motion.h1
          initial={{ opacity: 0, y: 25 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.7 }}
          style={{
            fontFamily: "'Inter', system-ui, sans-serif",
            fontSize: "clamp(58px, 6vw, 96px)",
            fontWeight: 800,
            lineHeight: 1.02,
            letterSpacing: "-0.05em",
            marginBottom: 28,
            color: "#0b0b0b",
          }}
        >
          <div>The Leading</div>
          <div>AI Code Review</div>
          <div
            style={{
              background:
                "linear-gradient(90deg,#111827 0%,#374151 60%,#6b7280 100%)",
              WebkitBackgroundClip: "text",
              color: "transparent",
            }}
          >
            Platform
          </div>
        </motion.h1>

        <motion.p
          initial={{ opacity: 0, y: 25 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.7, delay: 0.15 }}
          style={{
            fontFamily: "'Inter', system-ui, sans-serif",
            fontSize: 18,
            fontWeight: 400,
            color: "#525252",
            maxWidth: 620,
            margin: "0 auto 48px",
            lineHeight: 1.7,
          }}
        >
          Build and ship secure code in minutes — no IT bottlenecks,
          no manual reviews. Diff-aware AI that understands your
          repository context.
        </motion.p>

        <motion.div
          initial={{ opacity: 0, y: 25 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.7, delay: 0.25 }}
          style={{
            display: "flex",
            justifyContent: "center",
            gap: 16,
            flexWrap: "wrap",
            marginBottom: 100,
          }}
        >
          <a
            href={`${apiUrl}/api/auth/login`}
            style={{
              background: "#0f172a",
              color: "#fff",
              padding: "16px 36px",
              borderRadius: 999,
              fontWeight: 600,
              fontSize: 15,
              textDecoration: "none",
              fontFamily: "'Inter', system-ui, sans-serif",
            }}
          >
            Get Started — It’s Free
          </a>

          <a
            href="#how-it-works"
            style={{
              background: "#fff",
              border: "1px solid #e5e7eb",
              color: "#111",
              padding: "16px 36px",
              borderRadius: 999,
              fontWeight: 600,
              fontSize: 15,
              textDecoration: "none",
              fontFamily: "'Inter', system-ui, sans-serif",
            }}
          >
            See how it works
          </a>
        </motion.div>
      </div>

      {/* ================= HERO CARD ================= */}
      <div
        style={{
          maxWidth: 1300,
          margin: "0 auto",
          padding: "0 24px",
        }}
      >
        <motion.div style={{ y: cardY }}>
          <div
            style={{
              borderRadius: 40,
              position: "relative",
              overflow: "hidden",
              height: "clamp(480px, 52vw, 680px)",
              background: "#0f172a",
              boxShadow: "0 70px 140px rgba(0,0,0,0.25)",
            }}
          >
            {/* Soft animated glow */}
            <motion.div
              animate={{ opacity: [0.4, 0.7, 0.4] }}
              transition={{ duration: 6, repeat: Infinity }}
              style={{
                position: "absolute",
                width: 500,
                height: 500,
                background:
                  "radial-gradient(circle, rgba(99,102,241,0.35), transparent 70%)",
                top: "50%",
                left: "50%",
                transform: "translate(-50%, -50%)",
                filter: "blur(80px)",
              }}
            />

            {/* AI BOT IMAGE */}
            <div
              style={{
                position: "absolute",
                inset: 0,
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                pointerEvents: "none",
              }}
            >
              <img
                src="https://images.unsplash.com/photo-1677442136019-21780ecad995?q=80&w=1200&auto=format&fit=crop"
                alt="AI Bot"
                style={{
                  width: "360px",
                  maxWidth: "60%",
                  opacity: 0.95,
                  filter:
                    "drop-shadow(0 50px 80px rgba(0,0,0,0.6))",
                }}
              />
            </div>

            {/* FLOATING CARDS */}
            <FloatingCard
              top={40}
              left={40}
              bg="#1e293b"
              shape="rounded"
              title="Quality Score"
              subtitle="67 • Needs improvement"
            />

            <FloatingCard
              top={40}
              right={40}
              bg="#312e81"
              shape="square"
              title="AI Co-Pilot"
              subtitle="BOT • Active"
            />

            <FloatingCard
              bottom={40}
              left={40}
              bg="#064e3b"
              shape="capsule"
              title="PR #48"
              subtitle="Awaiting Review"
            />

            <FloatingCard
              bottom={40}
              right={40}
              bg="#7f1d1d"
              shape="glass"
              title="Security"
              subtitle="2 Critical Issues"
            />
          </div>
        </motion.div>
      </div>

      {/* ================= LOGO STRIP ================= */}
      <div
        style={{
          display: "flex",
          justifyContent: "center",
          gap: 60,
          flexWrap: "wrap",
          padding: "80px 24px",
          borderTop: "1px solid #f1f1f1",
          marginTop: 80,
          fontFamily: "'Inter', system-ui, sans-serif",
          fontWeight: 600,
          fontSize: 14,
          color: "#9ca3af",
        }}
      >
        {["GitHub", "GitLab", "Bitbucket", "Vercel", "Railway"].map(
          (name) => (
            <span key={name}>{name}</span>
          )
        )}
      </div>
    </section>
  );
}

/* ================= FLOATING CARD COMPONENT ================= */

function FloatingCard({
  top,
  bottom,
  left,
  right,
  bg,
  shape,
  title,
  subtitle,
}: any) {
  const borderRadius =
    shape === "square"
      ? 12
      : shape === "capsule"
      ? 999
      : shape === "glass"
      ? 24
      : 18;

  return (
    <motion.div
      initial={{ opacity: 0, y: 20, scale: 0.9 }}
      animate={{ opacity: 1, y: [0, -14, 0] }}
      transition={{
        opacity: { duration: 0.6 },
        y: { duration: 5, repeat: Infinity },
      }}
      style={{
        position: "absolute",
        top,
        bottom,
        left,
        right,
        background:
          shape === "glass"
            ? "rgba(255,255,255,0.08)"
            : bg,
        backdropFilter:
          shape === "glass" ? "blur(18px)" : undefined,
        border:
          shape === "glass"
            ? "1px solid rgba(255,255,255,0.2)"
            : "none",
        borderRadius,
        padding: "18px 22px",
        minWidth: 210,
        color: "#fff",
        boxShadow: "0 25px 50px rgba(0,0,0,0.4)",
        fontFamily: "'Inter', system-ui, sans-serif",
      }}
    >
      <div style={{ fontWeight: 600, fontSize: 15 }}>
        {title}
      </div>
      <div style={{ fontSize: 13, opacity: 0.8 }}>
        {subtitle}
      </div>
    </motion.div>
  );
}