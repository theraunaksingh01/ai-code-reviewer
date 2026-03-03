"use client";
import { useState, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";

const navLinks = ["Features", "How it works", "Pricing", "Docs"];

export default function Navbar({ apiUrl }: { apiUrl: string }) {
  const [scrolled, setScrolled] = useState(false);
  const [menuOpen, setMenuOpen] = useState(false);

  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 24);
    window.addEventListener("scroll", onScroll);
    return () => window.removeEventListener("scroll", onScroll);
  }, []);

  // Lock body scroll when menu open
  useEffect(() => {
    document.body.style.overflow = menuOpen ? "hidden" : "";
    return () => { document.body.style.overflow = ""; };
  }, [menuOpen]);

  return (
    <>
      <motion.nav
        initial={{ y: -80, opacity: 0 }}
        animate={{ y: 0, opacity: 1 }}
        transition={{ duration: 0.6, ease: [0.22, 1, 0.36, 1] }}
        style={{
          position: "fixed", top: 0, left: 0, right: 0, zIndex: 200,
          borderBottom: scrolled ? "1px solid #e8e8e8" : "1px solid transparent",
          background: scrolled ? "rgba(255,255,255,0.92)" : "rgba(255,255,255,0)",
          backdropFilter: scrolled ? "blur(20px)" : "none",
          transition: "background 0.35s, border-color 0.35s, backdrop-filter 0.35s",
        }}
      >
        <div style={{
          maxWidth: 1120, margin: "0 auto",
          padding: "0 28px",
          height: 64,
          display: "flex", alignItems: "center", justifyContent: "space-between",
        }}>
          {/* Logo */}
          <a href="/" style={{ display: "flex", alignItems: "center", gap: 9, textDecoration: "none", color: "#0a0a0a" }}>
            <div style={{
              width: 34, height: 34, background: "#0a0a0a",
              borderRadius: 9, display: "flex", alignItems: "center", justifyContent: "center",
              fontSize: 17,
            }}>🛡️</div>
            <span style={{ fontFamily: "'Syne', sans-serif", fontSize: 17, fontWeight: 700, letterSpacing: "-0.02em" }}>
              CodeSentinel
            </span>
          </a>

          {/* Desktop nav */}
          <div style={{ display: "flex", alignItems: "center", gap: 36 }} className="desktop-nav">
            {navLinks.map((link) => (
              <a
                key={link}
                href={`#${link.toLowerCase().replace(/ /g, "-")}`}
                style={{
                  fontFamily: "'DM Sans', sans-serif",
                  fontSize: 14, color: "#555", textDecoration: "none",
                  transition: "color 0.2s",
                }}
                onMouseEnter={(e) => (e.currentTarget.style.color = "#0a0a0a")}
                onMouseLeave={(e) => (e.currentTarget.style.color = "#555")}
              >
                {link}
              </a>
            ))}
          </div>

          {/* Desktop actions */}
          <div style={{ display: "flex", gap: 10, alignItems: "center" }} className="desktop-actions">
            <a
              href={`${apiUrl}/api/auth/login`}
              style={{
                fontFamily: "'DM Sans', sans-serif",
                background: "transparent", color: "#0a0a0a",
                border: "1.5px solid #e0e0e0", borderRadius: 100,
                padding: "9px 20px", fontSize: 13, fontWeight: 500,
                cursor: "pointer", textDecoration: "none",
                transition: "border-color 0.2s",
              }}
              onMouseEnter={(e) => (e.currentTarget.style.borderColor = "#aaa")}
              onMouseLeave={(e) => (e.currentTarget.style.borderColor = "#e0e0e0")}
            >
              Sign in
            </a>
            <a
              href={`${apiUrl}/api/auth/login`}
              style={{
                fontFamily: "'DM Sans', sans-serif",
                background: "#0a0a0a", color: "#fff",
                border: "none", borderRadius: 100,
                padding: "9px 20px", fontSize: 13, fontWeight: 500,
                cursor: "pointer", textDecoration: "none",
                transition: "background 0.2s",
              }}
              onMouseEnter={(e) => (e.currentTarget.style.background = "#333")}
              onMouseLeave={(e) => (e.currentTarget.style.background = "#0a0a0a")}
            >
              Get Started — It's Free →
            </a>
          </div>

          {/* Hamburger */}
          <button
            onClick={() => setMenuOpen(!menuOpen)}
            className="hamburger"
            style={{
              display: "none",
              background: "none", border: "none",
              cursor: "pointer", padding: 8,
              flexDirection: "column", gap: 5,
              alignItems: "flex-end",
            }}
          >
            <motion.span
              animate={{ rotate: menuOpen ? 45 : 0, y: menuOpen ? 7 : 0 }}
              transition={{ duration: 0.3 }}
              style={{ display: "block", width: 22, height: 2, background: "#0a0a0a", borderRadius: 2 }}
            />
            <motion.span
              animate={{ opacity: menuOpen ? 0 : 1, scaleX: menuOpen ? 0 : 1 }}
              transition={{ duration: 0.2 }}
              style={{ display: "block", width: 16, height: 2, background: "#0a0a0a", borderRadius: 2 }}
            />
            <motion.span
              animate={{ rotate: menuOpen ? -45 : 0, y: menuOpen ? -7 : 0 }}
              transition={{ duration: 0.3 }}
              style={{ display: "block", width: 22, height: 2, background: "#0a0a0a", borderRadius: 2 }}
            />
          </button>
        </div>
      </motion.nav>

      {/* Mobile menu */}
      <AnimatePresence>
        {menuOpen && (
          <motion.div
            key="mobile-menu"
            initial={{ opacity: 0, y: -20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -20 }}
            transition={{ duration: 0.35, ease: [0.22, 1, 0.36, 1] }}
            style={{
              position: "fixed", top: 64, left: 0, right: 0, bottom: 0,
              background: "#fff", zIndex: 199,
              display: "flex", flexDirection: "column",
              padding: "32px 28px",
            }}
          >
            {navLinks.map((link, i) => (
              <motion.a
                key={link}
                href={`#${link.toLowerCase().replace(/ /g, "-")}`}
                initial={{ opacity: 0, x: -20 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: i * 0.06 + 0.1 }}
                onClick={() => setMenuOpen(false)}
                style={{
                  fontFamily: "'Syne', sans-serif",
                  fontSize: 28, fontWeight: 700,
                  color: "#0a0a0a", textDecoration: "none",
                  padding: "16px 0",
                  borderBottom: "1px solid #f0f0f0",
                  letterSpacing: "-0.02em",
                }}
              >
                {link}
              </motion.a>
            ))}

            <div style={{ marginTop: "auto", display: "flex", flexDirection: "column", gap: 12 }}>
              <a
                href={`${apiUrl}/api/auth/login`}
                style={{
                  fontFamily: "'DM Sans', sans-serif",
                  background: "transparent", color: "#0a0a0a",
                  border: "1.5px solid #e0e0e0", borderRadius: 100,
                  padding: "14px 24px", fontSize: 15, fontWeight: 500,
                  textDecoration: "none", textAlign: "center",
                }}
              >
                Sign in
              </a>
              <a
                href={`${apiUrl}/api/auth/login`}
                style={{
                  fontFamily: "'DM Sans', sans-serif",
                  background: "#0a0a0a", color: "#fff",
                  border: "none", borderRadius: 100,
                  padding: "14px 24px", fontSize: 15, fontWeight: 500,
                  textDecoration: "none", textAlign: "center",
                }}
              >
                Get Started — It's Free →
              </a>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      <style>{`
        @media (max-width: 768px) {
          .desktop-nav, .desktop-actions { display: none !important; }
          .hamburger { display: flex !important; }
        }
      `}</style>
    </>
  );
}