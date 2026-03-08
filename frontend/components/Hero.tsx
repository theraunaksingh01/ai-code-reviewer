"use client";

import { useEffect } from "react";
import { motion } from "framer-motion";

// ── Canvas rainbow trail (ported from 21st.dev) ───────────
function renderCanvas() {
  const canvas = document.getElementById("hero-canvas") as HTMLCanvasElement;
  if (!canvas) return;
  const ctx = canvas.getContext("2d") as any;
  if (!ctx) return;

  ctx.running = true;
  ctx.frame = 1;

  const E = {
    friction: 0.5,
    trails: 80,
    size: 50,
    dampening: 0.025,
    tension: 0.99,
  };

  const pos: { x: number; y: number } = { x: 0, y: 0 };
  let lines: any[] = [];

  function Node(this: any) {
    this.x = 0; this.y = 0; this.vy = 0; this.vx = 0;
  }

  function Oscillator(this: any, opts: any) {
    this.phase = opts.phase || 0;
    this.offset = opts.offset || 0;
    this.frequency = opts.frequency || 0.001;
    this.amplitude = opts.amplitude || 1;
  }
  Oscillator.prototype.update = function () {
    this.phase += this.frequency;
    return this.offset + Math.sin(this.phase) * this.amplitude;
  };

  const f = new (Oscillator as any)({
    phase: Math.random() * 2 * Math.PI,
    amplitude: 85,
    frequency: 0.0015,
    offset: 285,
  });

  function Line(this: any, opts: any) {
    this.spring = opts.spring + 0.1 * Math.random() - 0.05;
    this.friction = E.friction + 0.01 * Math.random() - 0.005;
    this.nodes = [];
    for (let i = 0; i < E.size; i++) {
      const node = new (Node as any)();
      node.x = pos.x;
      node.y = pos.y;
      this.nodes.push(node);
    }
  }

  Line.prototype.update = function () {
    let spring = this.spring;
    let node = this.nodes[0];
    node.vx += (pos.x - node.x) * spring;
    node.vy += (pos.y - node.y) * spring;
    for (let i = 0; i < this.nodes.length; i++) {
      node = this.nodes[i];
      if (i > 0) {
        const prev = this.nodes[i - 1];
        node.vx += (prev.x - node.x) * spring;
        node.vy += (prev.y - node.y) * spring;
        node.vx += prev.vx * E.dampening;
        node.vy += prev.vy * E.dampening;
      }
      node.vx *= this.friction;
      node.vy *= this.friction;
      node.x += node.vx;
      node.y += node.vy;
      spring *= E.tension;
    }
  };

  Line.prototype.draw = function () {
    let x = this.nodes[0].x;
    let y = this.nodes[0].y;
    ctx.beginPath();
    ctx.moveTo(x, y);
    for (let i = 1; i < this.nodes.length - 2; i++) {
      const a = this.nodes[i];
      const b = this.nodes[i + 1];
      x = 0.5 * (a.x + b.x);
      y = 0.5 * (a.y + b.y);
      ctx.quadraticCurveTo(a.x, a.y, x, y);
    }
    const a = this.nodes[this.nodes.length - 2];
    const b = this.nodes[this.nodes.length - 1];
    ctx.quadraticCurveTo(a.x, a.y, b.x, b.y);
    ctx.stroke();
    ctx.closePath();
  };

  function initLines() {
    lines = [];
    for (let i = 0; i < E.trails; i++) {
      lines.push(new (Line as any)({ spring: 0.45 + (i / E.trails) * 0.025 }));
    }
  }

  function render() {
    if (!ctx.running) return;
    ctx.globalCompositeOperation = "source-over";
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    ctx.globalCompositeOperation = "lighter";
    ctx.strokeStyle = `hsla(${Math.round(f.update())},100%,50%,0.025)`;
    ctx.lineWidth = 10;
    for (const line of lines) {
      line.update();
      line.draw();
    }
    ctx.frame++;
    window.requestAnimationFrame(render);
  }

  function resize() {
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
  }

  function onMove(e: any) {
    if (e.touches) {
      pos.x = e.touches[0].pageX;
      pos.y = e.touches[0].pageY;
    } else {
      pos.x = e.clientX;
      pos.y = e.clientY;
    }
    e.preventDefault();
  }

  function onTouchStart(e: any) {
    if (e.touches.length === 1) {
      pos.x = e.touches[0].pageX;
      pos.y = e.touches[0].pageY;
    }
  }

  function bootstrap(e: any) {
    document.removeEventListener("mousemove", bootstrap);
    document.removeEventListener("touchstart", bootstrap);
    document.addEventListener("mousemove", onMove, { passive: false });
    document.addEventListener("touchmove", onMove, { passive: false });
    document.addEventListener("touchstart", onTouchStart);
    onMove(e);
    initLines();
    render();
  }

  document.addEventListener("mousemove", bootstrap);
  document.addEventListener("touchstart", bootstrap);
  window.addEventListener("resize", resize);
  window.addEventListener("focus", () => { if (!ctx.running) { ctx.running = true; render(); } });
  window.addEventListener("blur", () => { ctx.running = true; });
  resize();

  return () => {
    ctx.running = false;
    document.removeEventListener("mousemove", bootstrap);
    document.removeEventListener("mousemove", onMove);
    document.removeEventListener("touchstart", bootstrap);
    document.removeEventListener("touchmove", onMove);
    document.removeEventListener("touchstart", onTouchStart);
    window.removeEventListener("resize", resize);
  };
}

// ── Hero Component ────────────────────────────────────────
export default function Hero({ apiUrl }: { apiUrl: string }) {
  useEffect(() => {
    const cleanup = renderCanvas();
    return cleanup;
  }, []);

  return (
    <section style={{ position: "relative", minHeight: "100vh", background: "#fff", display: "flex", alignItems: "center", justifyContent: "center", overflow: "hidden" }}>

      {/* Rainbow canvas trail */}
      <canvas
        id="hero-canvas"
        style={{
          position: "absolute", inset: 0,
          width: "100%", height: "100%",
          pointerEvents: "none",
          zIndex: 0,
        }}
      />

      {/* Content */}
      <div style={{ position: "relative", zIndex: 10, textAlign: "center", padding: "120px 24px 80px", maxWidth: 900, margin: "0 auto" }}>

        {/* Badge */}
        <motion.div
          initial={{ opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5, ease: "easeOut" }}
          style={{ display: "inline-flex", alignItems: "center", gap: 8, marginBottom: 32 }}
        >
          <div style={{
            display: "flex", alignItems: "center", gap: 8,
            background: "#f5f5f5", border: "1px solid #e8e8e8",
            borderRadius: 100, padding: "6px 14px",
            fontSize: 13, color: "#555",
            fontFamily: "'DM Sans', sans-serif",
          }}>
            <span style={{ position: "relative", display: "flex", alignItems: "center", justifyContent: "center", width: 10, height: 10 }}>
              <span style={{ position: "absolute", width: "100%", height: "100%", borderRadius: "50%", background: "#22c55e", opacity: 0.75, animation: "ping 1.5s ease-in-out infinite" }} />
              <span style={{ position: "relative", width: 6, height: 6, borderRadius: "50%", background: "#22c55e", display: "inline-block" }} />
            </span>
            AI-Powered Code Review — Now Available
          </div>
        </motion.div>

        {/* Heading */}
        <motion.div
          initial={{ opacity: 0, y: 24 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, delay: 0.1, ease: "easeOut" }}
          style={{
            position: "relative",
            border: "1px solid #e8e8e8",
            borderRadius: 24,
            padding: "48px 40px",
            marginBottom: 32,
            background: "rgba(255,255,255,0.7)",
            backdropFilter: "blur(8px)",
          }}
        >
          {/* Corner plus signs */}
          {[
            { top: -10, left: -10 },
            { top: -10, right: -10 },
            { bottom: -10, left: -10 },
            { bottom: -10, right: -10 },
          ].map((pos, i) => (
            <svg key={i} width="20" height="20" viewBox="0 0 20 20" style={{ position: "absolute", ...pos as any }}>
              <line x1="10" y1="0" x2="10" y2="20" stroke="#0a0a0a" strokeWidth="2.5" />
              <line x1="0" y1="10" x2="20" y2="10" stroke="#0a0a0a" strokeWidth="2.5" />
            </svg>
          ))}

          <h1 style={{
            fontFamily: "'Plus Jakarta Sans', sans-serif",
            fontSize: "clamp(40px, 7vw, 80px)",
            fontWeight: 800,
            letterSpacing: "-2px",
            lineHeight: 1.05,
            color: "#0a0a0a",
            margin: 0,
          }}>
            The Leading AI<br />Code Review Platform
          </h1>

          {/* Live indicator */}
          <div style={{ display: "flex", alignItems: "center", justifyContent: "center", gap: 6, marginTop: 16 }}>
            <span style={{ position: "relative", display: "flex", alignItems: "center", justifyContent: "center", width: 10, height: 10 }}>
              <span style={{ position: "absolute", width: "100%", height: "100%", borderRadius: "50%", background: "#22c55e", opacity: 0.75, animation: "ping 1.5s ease-in-out infinite" }} />
              <span style={{ position: "relative", width: 6, height: 6, borderRadius: "50%", background: "#22c55e", display: "inline-block" }} />
            </span>
            <span style={{ fontSize: 12, color: "#22c55e", fontFamily: "'DM Sans', sans-serif", fontWeight: 500 }}>Live on GitHub</span>
          </div>
        </motion.div>

        {/* Description */}
        <motion.p
          initial={{ opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, delay: 0.2, ease: "easeOut" }}
          style={{
            fontFamily: "'DM Sans', sans-serif",
            fontSize: "clamp(15px, 2vw, 18px)",
            color: "#666",
            maxWidth: 600,
            margin: "0 auto 40px",
            lineHeight: 1.7,
          }}
        >
          Automatically catches security vulnerabilities, bugs, and code smells on every PR.
          Scores quality 0–100, auto-generates fix PRs, and learns your codebase over time.
        </motion.p>

        {/* CTA buttons */}
        <motion.div
          initial={{ opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, delay: 0.3, ease: "easeOut" }}
          style={{ display: "flex", gap: 12, justifyContent: "center", flexWrap: "wrap" }}
        >
          <a
            href={`${apiUrl}/api/auth/login`}
            style={{
              fontFamily: "'DM Sans', sans-serif",
              background: "#0a0a0a", color: "#fff",
              borderRadius: 100, padding: "14px 28px",
              fontSize: 14, fontWeight: 600,
              textDecoration: "none", display: "inline-flex",
              alignItems: "center", gap: 8,
              transition: "background 0.2s, transform 0.2s",
              boxShadow: "0 4px 20px rgba(0,0,0,0.15)",
            }}
            onMouseEnter={e => {
              (e.currentTarget as HTMLElement).style.background = "#333";
              (e.currentTarget as HTMLElement).style.transform = "translateY(-1px)";
            }}
            onMouseLeave={e => {
              (e.currentTarget as HTMLElement).style.background = "#0a0a0a";
              (e.currentTarget as HTMLElement).style.transform = "translateY(0)";
            }}
          >
            Get Started — It's Free →
          </a>
          <a
            href="#features"
            style={{
              fontFamily: "'DM Sans', sans-serif",
              background: "transparent", color: "#0a0a0a",
              border: "1.5px solid #e0e0e0", borderRadius: 100,
              padding: "14px 28px", fontSize: 14, fontWeight: 500,
              textDecoration: "none", display: "inline-flex",
              alignItems: "center", gap: 8,
              transition: "border-color 0.2s, transform 0.2s",
            }}
            onMouseEnter={e => {
              (e.currentTarget as HTMLElement).style.borderColor = "#aaa";
              (e.currentTarget as HTMLElement).style.transform = "translateY(-1px)";
            }}
            onMouseLeave={e => {
              (e.currentTarget as HTMLElement).style.borderColor = "#e0e0e0";
              (e.currentTarget as HTMLElement).style.transform = "translateY(0)";
            }}
          >
            See How It Works
          </a>
        </motion.div>

        {/* Stats row */}
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ duration: 0.8, delay: 0.5 }}
          style={{ display: "flex", gap: 40, justifyContent: "center", marginTop: 64, flexWrap: "wrap" }}
        >
          {[
            { value: "7+", label: "Vulnerability Types" },
            { value: "< 30s", label: "Review Time" },
            { value: "0–100", label: "Quality Scoring" },
            { value: "RAG", label: "Codebase Learning" },
          ].map((stat) => (
            <div key={stat.label} style={{ textAlign: "center" }}>
              <div style={{
                fontFamily: "'Plus Jakarta Sans', sans-serif",
                fontSize: 28, fontWeight: 800,
                color: "#0a0a0a", letterSpacing: "-1px",
              }}>{stat.value}</div>
              <div style={{ fontFamily: "'DM Sans', sans-serif", fontSize: 12, color: "#999", marginTop: 4 }}>{stat.label}</div>
            </div>
          ))}
        </motion.div>
      </div>

      <style>{`
        @keyframes ping {
          0% { transform: scale(1); opacity: 0.75; }
          75%, 100% { transform: scale(2); opacity: 0; }
        }
      `}</style>
    </section>
  );
}