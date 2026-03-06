"use client";

import { useEffect, useState, useRef } from "react";
import { useSearchParams, useRouter } from "next/navigation";
import {
  Shield, GitPullRequest, AlertTriangle, CheckCircle,
  XCircle, TrendingUp, Code2, LogOut, Activity,
  MessageSquare, Clock, Zap, Lock, GitBranch, Globe
} from "lucide-react";
import {
  LineChart, Line, XAxis, YAxis, CartesianGrid,
  Tooltip, ResponsiveContainer, BarChart, Bar
} from "recharts";
import axios from "axios";

const API = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

// ─── Design Tokens ────────────────────────────────────────
const C = {
  bg: "#080810",
  surface: "#0f0f1a",
  surfaceHover: "#141428",
  border: "rgba(255,255,255,0.07)",
  borderHover: "rgba(255,255,255,0.14)",
  accent: "#00ff88",
  accentDim: "rgba(0,255,136,0.12)",
  accentGlow: "rgba(0,255,136,0.25)",
  red: "#ff4466",
  redDim: "rgba(255,68,102,0.12)",
  orange: "#ff8c42",
  orangeDim: "rgba(255,140,66,0.12)",
  yellow: "#ffd166",
  yellowDim: "rgba(255,209,102,0.12)",
  blue: "#4d9fff",
  blueDim: "rgba(77,159,255,0.12)",
  text: "#f0f0f8",
  textMid: "rgba(240,240,248,0.5)",
  textDim: "rgba(240,240,248,0.25)",
  textFaint: "rgba(240,240,248,0.12)",
};

// ─── Helpers ──────────────────────────────────────────────
function timeAgo(d: string) {
  const s = Math.floor((Date.now() - new Date(d).getTime()) / 1000);
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

function scoreColor(s: number) {
  if (s >= 80) return C.accent;
  if (s >= 50) return C.yellow;
  return C.red;
}

// ─── Score Arc ────────────────────────────────────────────
function ScoreArc({ score }: { score: number }) {
  const r = 54, cx = 64, cy = 64;
  const circ = 2 * Math.PI * r;
  const pct = Math.max(0, Math.min(score, 100)) / 100;
  const dash = pct * circ;
  const col = scoreColor(score);
  return (
    <div style={{ position: "relative", width: 128, height: 128 }}>
      <svg width="128" height="128" style={{ transform: "rotate(-90deg)" }}>
        <circle cx={cx} cy={cy} r={r} fill="none" stroke={C.textFaint} strokeWidth="8" />
        <circle cx={cx} cy={cy} r={r} fill="none" stroke={col} strokeWidth="8"
          strokeDasharray={`${dash} ${circ}`} strokeLinecap="round"
          style={{ filter: `drop-shadow(0 0 8px ${col})`, transition: "stroke-dasharray 1.2s cubic-bezier(.4,0,.2,1)" }}
        />
      </svg>
      <div style={{ position: "absolute", inset: 0, display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center" }}>
        <span style={{ fontSize: 28, fontWeight: 900, color: col, letterSpacing: "-1px", lineHeight: 1, fontFamily: "'Outfit', sans-serif" }}>{score}</span>
        <span style={{ fontSize: 11, color: C.textDim, marginTop: 2 }}>/ 100</span>
      </div>
    </div>
  );
}

// ─── Stat Card ────────────────────────────────────────────
function StatCard({ label, value, sub, icon, color }: any) {
  const [hov, setHov] = useState(false);
  return (
    <div
      onMouseEnter={() => setHov(true)}
      onMouseLeave={() => setHov(false)}
      style={{
        background: hov ? C.surfaceHover : C.surface,
        border: `1px solid ${hov ? C.borderHover : C.border}`,
        borderRadius: 16, padding: "22px 24px",
        transition: "all 0.2s ease",
        cursor: "default",
        position: "relative", overflow: "hidden",
      }}
    >
      {/* Glow blob */}
      <div style={{
        position: "absolute", top: -20, right: -20, width: 80, height: 80,
        borderRadius: "50%", background: color,
        opacity: hov ? 0.15 : 0.07, filter: "blur(24px)",
        transition: "opacity 0.3s",
      }} />
      <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", marginBottom: 16 }}>
        <span style={{ fontSize: 11, fontWeight: 600, color: C.textDim, textTransform: "uppercase", letterSpacing: "0.1em" }}>{label}</span>
        <div style={{ width: 32, height: 32, borderRadius: 10, background: `${color}18`, display: "flex", alignItems: "center", justifyContent: "center" }}>
          {icon}
        </div>
      </div>
      <div style={{ fontSize: 36, fontWeight: 900, color: C.text, letterSpacing: "-1.5px", lineHeight: 1, fontFamily: "'Outfit', sans-serif" }}>{value}</div>
      <div style={{ fontSize: 12, color: C.textDim, marginTop: 6 }}>{sub}</div>
    </div>
  );
}

// ─── Badge ────────────────────────────────────────────────
function Pill({ children, color, bg }: { children: React.ReactNode; color: string; bg: string }) {
  return (
    <span style={{
      display: "inline-flex", alignItems: "center", gap: 4,
      padding: "3px 10px", borderRadius: 100,
      fontSize: 11, fontWeight: 600,
      color, background: bg,
      border: `1px solid ${color}30`,
      whiteSpace: "nowrap",
    }}>{children}</span>
  );
}

// ─── Custom Chart Tooltip ─────────────────────────────────
function ChartTip({ active, payload, label }: any) {
  if (!active || !payload?.length) return null;
  return (
    <div style={{ background: "#12121f", border: `1px solid ${C.border}`, borderRadius: 12, padding: "10px 14px", fontSize: 12 }}>
      <div style={{ color: C.textDim, marginBottom: 8, fontWeight: 600 }}>{label}</div>
      {payload.map((p: any) => (
        <div key={p.dataKey} style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 4 }}>
          <span style={{ width: 8, height: 8, borderRadius: 2, background: p.color, display: "inline-block" }} />
          <span style={{ color: C.textMid, textTransform: "capitalize" }}>{p.dataKey}:</span>
          <span style={{ color: C.text, fontWeight: 700 }}>{p.value}</span>
        </div>
      ))}
    </div>
  );
}

// ─── Tab Button ───────────────────────────────────────────
function Tab({ label, active, onClick }: any) {
  return (
    <button onClick={onClick} style={{
      padding: "9px 20px", borderRadius: 10, border: "none",
      background: active ? C.accent : "transparent",
      color: active ? "#000" : C.textDim,
      fontWeight: active ? 700 : 500,
      fontSize: 13, cursor: "pointer",
      transition: "all 0.2s",
      fontFamily: "'DM Sans', sans-serif",
      boxShadow: active ? `0 0 20px ${C.accentGlow}` : "none",
    }}>{label}</button>
  );
}

// ─── Empty State ──────────────────────────────────────────
function Empty({ Icon, msg }: { Icon: any; msg: string }) {
  return (
    <div style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", padding: "64px 0", color: C.textFaint }}>
      <Icon size={40} style={{ marginBottom: 12, opacity: 0.3 }} />
      <p style={{ fontSize: 13, color: C.textDim }}>{msg}</p>
    </div>
  );
}

// ─── Repo Row ─────────────────────────────────────────────
function RepoRow({ repo, isConnected, isConnecting, onConnect }: any) {
  const [hov, setHov] = useState(false);
  return (
    <div
      onMouseEnter={() => setHov(true)}
      onMouseLeave={() => setHov(false)}
      style={{
        display: "flex", alignItems: "center", justifyContent: "space-between",
        padding: "13px 16px", borderRadius: 12,
        background: isConnected ? C.accentDim : hov ? C.surfaceHover : "transparent",
        border: `1px solid ${isConnected ? C.accent + "30" : hov ? C.borderHover : C.border}`,
        transition: "all 0.15s",
      }}
    >
      <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
        <div style={{ width: 34, height: 34, borderRadius: 9, background: isConnected ? C.accentDim : C.textFaint, display: "flex", alignItems: "center", justifyContent: "center" }}>
          {isConnected ? <Shield size={15} color={C.accent} /> : <GitBranch size={15} color={C.textDim} />}
        </div>
        <div>
          <p style={{ fontWeight: 600, fontSize: 13, margin: 0, color: C.text }}>{repo.full_name}</p>
          <div style={{ display: "flex", alignItems: "center", gap: 10, marginTop: 3 }}>
            {repo.language && <span style={{ fontSize: 11, color: C.textDim }}>⬡ {repo.language}</span>}
            {repo.private && <span style={{ fontSize: 10, color: C.textFaint, background: C.textFaint, padding: "1px 6px", borderRadius: 4 }}>Private</span>}
          </div>
        </div>
      </div>
      {isConnected ? (
        <Pill color={C.accent} bg="rgba(0,255,136,0.08)">✓ Connected</Pill>
      ) : (
        <button
          onClick={onConnect}
          disabled={isConnecting}
          style={{
            background: isConnecting ? C.textFaint : C.accent,
            color: isConnecting ? C.textDim : "#000",
            border: "none", borderRadius: 9, padding: "8px 16px",
            fontSize: 12, fontWeight: 700, cursor: isConnecting ? "not-allowed" : "pointer",
            fontFamily: "'DM Sans', sans-serif", transition: "all 0.15s",
            display: "flex", alignItems: "center", gap: 6,
            boxShadow: isConnecting ? "none" : `0 0 16px ${C.accentGlow}`,
          }}
        >
          {isConnecting ? (
            <><div style={{ width: 12, height: 12, borderRadius: "50%", border: `2px solid ${C.textDim}`, borderTopColor: C.text, animation: "spin 0.8s linear infinite" }} /> Connecting...</>
          ) : (
            <><Zap size={12} /> Connect</>
          )}
        </button>
      )}
    </div>
  );
}

// ─── Review Row (extracted to fix Rules of Hooks) ────────
function ReviewRow({ r, isLast }: { r: any; isLast: boolean }) {
  const [hov, setHov] = useState(false);
  const sc = Math.round(r.quality_score);
  const isApprove = r.verdict === "APPROVE";
  const isBot = r.pr_author?.includes("[bot]");
  return (
    <div
      onMouseEnter={() => setHov(true)}
      onMouseLeave={() => setHov(false)}
      style={{
        padding: "16px 24px", display: "flex", alignItems: "center", gap: 16,
        borderBottom: !isLast ? `1px solid ${C.border}` : "none",
        background: hov ? C.surfaceHover : "transparent",
        transition: "background 0.15s",
      }}>
      <div style={{ width: 32, height: 32, borderRadius: 10, flexShrink: 0, display: "flex", alignItems: "center", justifyContent: "center", background: isApprove ? "rgba(0,255,136,0.1)" : "rgba(255,68,102,0.1)" }}>
        {isApprove ? <CheckCircle size={15} color={C.accent} /> : r.verdict === "REQUEST_CHANGES" ? <XCircle size={15} color={C.red} /> : <MessageSquare size={15} color={C.yellow} />}
      </div>
      <div style={{ flex: 1, minWidth: 0 }}>
        <p style={{ fontWeight: 600, fontSize: 14, margin: 0, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis", color: isBot ? C.textMid : C.text }}>
          {isBot && <span style={{ fontSize: 10, background: C.accentDim, color: C.accent, borderRadius: 4, padding: "1px 6px", marginRight: 6, fontWeight: 700 }}>BOT</span>}
          {r.pr_title}
        </p>
        <div style={{ display: "flex", alignItems: "center", gap: 12, marginTop: 5 }}>
          <span style={{ fontSize: 12, color: C.textDim, display: "flex", alignItems: "center", gap: 4 }}>
            <GitPullRequest size={11} /> PR #{r.pr_number}
          </span>
          <span style={{ fontSize: 12, color: C.textDim }}>@{r.pr_author}</span>
          <span style={{ fontSize: 12, color: C.textFaint, display: "flex", alignItems: "center", gap: 4 }}>
            <Clock size={11} />{timeAgo(r.reviewed_at)}
          </span>
        </div>
      </div>
      <div style={{ display: "flex", gap: 6, flexShrink: 0 }}>
        {r.critical_count > 0 && <Pill color={C.red} bg={C.redDim}>{r.critical_count} critical</Pill>}
        {r.high_count > 0 && <Pill color={C.orange} bg={C.orangeDim}>{r.high_count} high</Pill>}
        {r.medium_count > 0 && <Pill color={C.yellow} bg={C.yellowDim}>{r.medium_count} med</Pill>}
        {r.critical_count === 0 && r.high_count === 0 && r.medium_count === 0 && (
          <Pill color={C.accent} bg={C.accentDim}>Clean ✓</Pill>
        )}
      </div>
      <div style={{ fontSize: 26, fontWeight: 900, fontFamily: "'Outfit', sans-serif", color: scoreColor(sc), minWidth: 48, textAlign: "right", letterSpacing: "-1px" }}>{sc}</div>
    </div>
  );
}

// ─── Main ─────────────────────────────────────────────────
export default function Dashboard() {
  const searchParams = useSearchParams();
  const router = useRouter();
  const [user, setUser] = useState<any>(null);
  const [overview, setOverview] = useState<any>(null);
  const [reviews, setReviews] = useState<any[]>([]);
  const [heatmap, setHeatmap] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [tab, setTab] = useState("reviews");
  const [availableRepos, setAvailableRepos] = useState<any[]>([]);
  const [connectedRepos, setConnectedRepos] = useState<any[]>([]);
  const [reposLoading, setReposLoading] = useState(false);
  const [connectingRepo, setConnectingRepo] = useState<string | null>(null);
  const [repoSearch, setRepoSearch] = useState("");

  const tokenRef = useRef<string>("");

  useEffect(() => {
    const t = searchParams.get("token") || localStorage.getItem("cs_token");
    if (!t) { router.push("/"); return; }
    localStorage.setItem("cs_token", t);
    tokenRef.current = t;
    const headers = { Authorization: `Bearer ${t}` };
    Promise.all([
      axios.get(`${API}/api/auth/me`, { headers }),
      axios.get(`${API}/api/analytics/overview`, { headers }),
      axios.get(`${API}/api/analytics/reviews`, { headers }),
      axios.get(`${API}/api/analytics/security-heatmap`, { headers }),
    ]).then(([u, o, r, h]) => {
      setUser(u.data); setOverview(o.data);
      setReviews(r.data); setHeatmap(h.data);
    }).catch((err) => {
      console.error("Dashboard load error:", err);
      // Only redirect if it's an auth error (401), not other failures
      if (err?.response?.status === 401) {
        localStorage.removeItem("cs_token");
        router.push("/");
      }
    }).finally(() => setLoading(false));
  }, []);

  // Load repos when repos tab is opened
  useEffect(() => {
    if (tab !== "repos") return;
    if (availableRepos.length > 0) return; // already loaded
    setReposLoading(true);
    const headers = { Authorization: `Bearer ${tokenRef.current}` };
    Promise.all([
      axios.get(`${API}/api/repos/available`, { headers }),
      axios.get(`${API}/api/repos`, { headers }),
    ]).then(([avail, connected]) => {
      setAvailableRepos(avail.data);
      setConnectedRepos(connected.data);
    }).catch(console.error)
      .finally(() => setReposLoading(false));
  }, [tab]);

  const connectRepo = async (repo: any) => {
    setConnectingRepo(repo.full_name);
    try {
      await axios.post(`${API}/api/repos/connect`, {
        full_name: repo.full_name,
        github_repo_id: repo.github_repo_id,
        language: repo.language,
      }, { headers: { Authorization: `Bearer ${tokenRef.current}` } });
      // Refresh connected repos
      const res = await axios.get(`${API}/api/repos`, { headers: { Authorization: `Bearer ${tokenRef.current}` } });
      setConnectedRepos(res.data);
    } catch (e: any) {
      alert(e?.response?.data?.detail || "Failed to connect repo");
    } finally {
      setConnectingRepo(null);
    }
  };

  if (loading) return (
    <div style={{ minHeight: "100vh", background: C.bg, display: "flex", alignItems: "center", justifyContent: "center", flexDirection: "column", gap: 16 }}>
      <div style={{ width: 52, height: 52, borderRadius: 16, background: C.accent, display: "flex", alignItems: "center", justifyContent: "center", boxShadow: `0 0 40px ${C.accentGlow}`, animation: "pulse 2s infinite" }}>
        <Shield size={28} color="#000" />
      </div>
      <p style={{ color: C.textDim, fontSize: 13, letterSpacing: "0.15em", textTransform: "uppercase" }}>Loading dashboard</p>
      <style>{`@keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.5} }`}</style>
    </div>
  );

  const avg = Math.round(overview?.average_quality_score ?? 0);
  const total = overview?.total_reviews ?? 0;
  const approvedPct = total > 0 ? Math.round(((overview?.approved_prs ?? 0) / total) * 100) : 0;

  const scoreTrend = [...reviews].reverse().slice(-12).map(r => ({ name: `#${r.pr_number}`, score: Math.round(r.quality_score) }));
  const sevTrend = [...reviews].reverse().slice(-10).map(r => ({ name: `#${r.pr_number}`, critical: r.critical_count, high: r.high_count, medium: r.medium_count }));

  return (
    <div style={{ minHeight: "100vh", background: C.bg, color: C.text, fontFamily: "'DM Sans', sans-serif" }}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Outfit:wght@400;600;700;900&family=DM+Sans:wght@400;500;600;700&display=swap');
        * { box-sizing: border-box; }
        ::-webkit-scrollbar { width: 6px; }
        ::-webkit-scrollbar-track { background: ${C.bg}; }
        ::-webkit-scrollbar-thumb { background: ${C.border}; border-radius: 3px; }
        @keyframes fadeUp { from { opacity:0; transform:translateY(16px); } to { opacity:1; transform:translateY(0); } }
        .fade-up { animation: fadeUp 0.5s ease forwards; }
      `}</style>

      {/* Fixed ambient glow */}
      <div style={{ position: "fixed", inset: 0, pointerEvents: "none", zIndex: 0,
        background: `radial-gradient(ellipse 60% 40% at 10% 0%, rgba(0,255,136,0.05) 0%, transparent 60%),
                     radial-gradient(ellipse 40% 30% at 90% 100%, rgba(77,159,255,0.04) 0%, transparent 60%)` }} />

      {/* Topbar */}
      <nav style={{
        position: "sticky", top: 0, zIndex: 100,
        background: "rgba(8,8,16,0.85)", backdropFilter: "blur(20px)",
        borderBottom: `1px solid ${C.border}`,
        padding: "0 32px", height: 64,
        display: "flex", alignItems: "center", justifyContent: "space-between",
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <div style={{ width: 36, height: 36, borderRadius: 11, background: C.accent, display: "flex", alignItems: "center", justifyContent: "center", boxShadow: `0 0 20px ${C.accentGlow}` }}>
            <Shield size={20} color="#000" />
          </div>
          <span style={{ fontFamily: "'Outfit', sans-serif", fontSize: 18, fontWeight: 700, letterSpacing: "-0.5px" }}>CodeSentinel</span>
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          {user && (
            <div style={{ display: "flex", alignItems: "center", gap: 10, background: C.surface, border: `1px solid ${C.border}`, borderRadius: 12, padding: "8px 14px" }}>
              <img src={user.avatar_url} alt="" style={{ width: 28, height: 28, borderRadius: "50%", border: `2px solid ${C.accentDim}` }} />
              <span style={{ fontSize: 13, fontWeight: 600, color: C.textMid }}>{user.username}</span>
            </div>
          )}
          <button
            onClick={() => { localStorage.removeItem("cs_token"); router.push("/"); }}
            style={{ display: "flex", alignItems: "center", gap: 6, background: "none", border: `1px solid ${C.border}`, borderRadius: 10, padding: "8px 14px", color: C.textDim, fontSize: 13, cursor: "pointer", transition: "all 0.2s", fontFamily: "'DM Sans', sans-serif" }}
            onMouseEnter={e => { (e.currentTarget as HTMLElement).style.borderColor = C.borderHover; (e.currentTarget as HTMLElement).style.color = C.text; }}
            onMouseLeave={e => { (e.currentTarget as HTMLElement).style.borderColor = C.border; (e.currentTarget as HTMLElement).style.color = C.textDim; }}
          >
            <LogOut size={14} /> Logout
          </button>
        </div>
      </nav>

      {/* Main content */}
      <div style={{ maxWidth: 1200, margin: "0 auto", padding: "40px 32px", position: "relative", zIndex: 1 }}>

        {/* Header row */}
        <div className="fade-up" style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", marginBottom: 40 }}>
          <div>
            <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 10 }}>
              <Activity size={13} color={C.accent} />
              <span style={{ fontSize: 11, fontWeight: 600, color: C.accent, textTransform: "uppercase", letterSpacing: "0.12em" }}>Live Dashboard</span>
            </div>
            <h1 style={{ fontFamily: "'Outfit', sans-serif", fontSize: 38, fontWeight: 900, letterSpacing: "-1.5px", lineHeight: 1.1, margin: 0 }}>
              Welcome back,{" "}
              <span style={{ background: `linear-gradient(135deg, ${C.accent}, #00ccff)`, WebkitBackgroundClip: "text", WebkitTextFillColor: "transparent" }}>
                {user?.username}
              </span>
            </h1>
            <p style={{ color: C.textDim, marginTop: 8, fontSize: 14 }}>Your code quality intelligence at a glance</p>
          </div>
          <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 8 }}>
            <ScoreArc score={avg} />
            <span style={{ fontSize: 11, color: C.textDim, textTransform: "uppercase", letterSpacing: "0.1em" }}>Avg Score</span>
          </div>
        </div>

        {/* Stats */}
        <div className="fade-up" style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 16, marginBottom: 32 }}>
          <StatCard label="Total Reviews" value={total} sub="pull requests analyzed" icon={<GitPullRequest size={16} color={C.blue} />} color={C.blue} />
          <StatCard label="Avg Quality" value={`${avg}/100`} sub={`${approvedPct}% approved`} icon={<TrendingUp size={16} color={C.accent} />} color={C.accent} />
          <StatCard label="Critical Issues" value={overview?.total_critical_issues ?? 0} sub={`${overview?.total_high_issues ?? 0} high severity`} icon={<AlertTriangle size={16} color={C.red} />} color={C.red} />
          <StatCard label="Repos Connected" value={overview?.repos_connected ?? 0} sub="active repositories" icon={<Code2 size={16} color={C.orange} />} color={C.orange} />
        </div>

        {/* Tabs */}
        <div className="fade-up" style={{ display: "flex", gap: 4, background: C.surface, border: `1px solid ${C.border}`, borderRadius: 14, padding: 4, width: "fit-content", marginBottom: 24 }}>
          <Tab label="PR Reviews" active={tab === "reviews"} onClick={() => setTab("reviews")} />
          <Tab label="Quality Trends" active={tab === "trends"} onClick={() => setTab("trends")} />
          <Tab label="Security Heatmap" active={tab === "security"} onClick={() => setTab("security")} />
          <Tab label="Repositories" active={tab === "repos"} onClick={() => setTab("repos")} />
        </div>

        {/* ── PR Reviews ── */}
        {tab === "reviews" && (
          <div style={{ background: C.surface, border: `1px solid ${C.border}`, borderRadius: 20, overflow: "hidden" }} className="fade-up">
            <div style={{ padding: "20px 24px", borderBottom: `1px solid ${C.border}`, display: "flex", alignItems: "center", justifyContent: "space-between" }}>
              <div>
                <h2 style={{ fontFamily: "'Outfit', sans-serif", fontWeight: 700, fontSize: 17, margin: 0 }}>Recent PR Reviews</h2>
                <p style={{ color: C.textDim, fontSize: 13, marginTop: 3 }}>All pull requests reviewed by CodeSentinel</p>
              </div>
              <Pill color={C.textMid} bg={C.textFaint}>{reviews.length} total</Pill>
            </div>
            {reviews.length === 0 ? <Empty Icon={GitPullRequest} msg="No reviews yet — open a PR to get started" /> : (
              reviews.map((r, i) => (
                <ReviewRow key={r.id} r={r} isLast={i === reviews.length - 1} />
              ))
            )}
          </div>
        )}

        {/* ── Trends ── */}
        {tab === "trends" && (
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 20 }} className="fade-up">
            {/* Score trend */}
            <div style={{ background: C.surface, border: `1px solid ${C.border}`, borderRadius: 20, padding: 24 }}>
              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 24 }}>
                <h3 style={{ fontFamily: "'Outfit', sans-serif", fontWeight: 700, fontSize: 15, margin: 0 }}>Quality Score Trend</h3>
                <div style={{ width: 8, height: 8, borderRadius: "50%", background: C.accent, boxShadow: `0 0 8px ${C.accent}` }} />
              </div>
              {scoreTrend.length > 0 ? (
                <ResponsiveContainer width="100%" height={220}>
                  <LineChart data={scoreTrend}>
                    <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.04)" />
                    <XAxis dataKey="name" tick={{ fill: C.textDim, fontSize: 11 }} axisLine={false} tickLine={false} />
                    <YAxis domain={[0, 100]} tick={{ fill: C.textDim, fontSize: 11 }} axisLine={false} tickLine={false} />
                    <Tooltip content={<ChartTip />} />
                    <Line type="monotone" dataKey="score" stroke={C.accent} strokeWidth={2.5}
                      dot={{ fill: C.accent, r: 3, strokeWidth: 0 }}
                      activeDot={{ r: 6, fill: C.accent, style: { filter: `drop-shadow(0 0 6px ${C.accent})` } }} />
                  </LineChart>
                </ResponsiveContainer>
              ) : <Empty Icon={TrendingUp} msg="No data yet" />}
            </div>

            {/* Severity chart */}
            <div style={{ background: C.surface, border: `1px solid ${C.border}`, borderRadius: 20, padding: 24 }}>
              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 24 }}>
                <h3 style={{ fontFamily: "'Outfit', sans-serif", fontWeight: 700, fontSize: 15, margin: 0 }}>Issues by Severity</h3>
                <div style={{ display: "flex", gap: 12 }}>
                  {[["Critical", C.red], ["High", C.orange], ["Medium", C.yellow]].map(([l, c]) => (
                    <span key={l} style={{ fontSize: 11, color: C.textDim, display: "flex", alignItems: "center", gap: 5 }}>
                      <span style={{ width: 8, height: 8, borderRadius: 2, background: c as string, display: "inline-block" }} />{l}
                    </span>
                  ))}
                </div>
              </div>
              {sevTrend.length > 0 ? (
                <ResponsiveContainer width="100%" height={220}>
                  <BarChart data={sevTrend} barSize={7} barGap={2}>
                    <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.04)" />
                    <XAxis dataKey="name" tick={{ fill: C.textDim, fontSize: 11 }} axisLine={false} tickLine={false} />
                    <YAxis tick={{ fill: C.textDim, fontSize: 11 }} axisLine={false} tickLine={false} />
                    <Tooltip content={<ChartTip />} />
                    <Bar dataKey="critical" fill={C.red} radius={[4, 4, 0, 0]} />
                    <Bar dataKey="high" fill={C.orange} radius={[4, 4, 0, 0]} />
                    <Bar dataKey="medium" fill={C.yellow} radius={[4, 4, 0, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              ) : <Empty Icon={AlertTriangle} msg="No data yet" />}
            </div>

            {/* Verdict breakdown */}
            <div style={{ background: C.surface, border: `1px solid ${C.border}`, borderRadius: 20, padding: 24, gridColumn: "1 / -1" }}>
              <h3 style={{ fontFamily: "'Outfit', sans-serif", fontWeight: 700, fontSize: 15, margin: "0 0 28px 0" }}>PR Verdict Breakdown</h3>
              <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 32 }}>
                {[
                  { label: "Approved", value: overview?.approved_prs ?? 0, color: C.accent },
                  { label: "Changes Requested", value: overview?.changes_requested ?? 0, color: C.red },
                  { label: "Total Reviewed", value: total, color: C.blue },
                ].map(item => {
                  const pct = total > 0 ? Math.round((item.value / total) * 100) : 0;
                  return (
                    <div key={item.label} style={{ textAlign: "center" }}>
                      <div style={{ fontFamily: "'Outfit', sans-serif", fontSize: 52, fontWeight: 900, color: item.color, lineHeight: 1, letterSpacing: "-2px", textShadow: `0 0 30px ${item.color}40` }}>{item.value}</div>
                      <div style={{ color: C.textDim, fontSize: 13, margin: "10px 0 14px" }}>{item.label}</div>
                      <div style={{ height: 4, borderRadius: 4, background: "rgba(255,255,255,0.06)", overflow: "hidden" }}>
                        <div style={{ height: "100%", width: `${pct}%`, background: item.color, borderRadius: 4, transition: "width 1.2s cubic-bezier(.4,0,.2,1)", boxShadow: `0 0 10px ${item.color}60` }} />
                      </div>
                      <div style={{ fontSize: 11, color: C.textFaint, marginTop: 6 }}>{pct}%</div>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>
        )}

        {/* ── Security Heatmap ── */}
        {tab === "security" && (
          <div style={{ background: C.surface, border: `1px solid ${C.border}`, borderRadius: 20, overflow: "hidden" }} className="fade-up">
            <div style={{ padding: "20px 24px", borderBottom: `1px solid ${C.border}` }}>
              <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                <Lock size={16} color={C.red} />
                <h2 style={{ fontFamily: "'Outfit', sans-serif", fontWeight: 700, fontSize: 17, margin: 0 }}>Security Vulnerability Heatmap</h2>
              </div>
              <p style={{ color: C.textDim, fontSize: 13, marginTop: 4 }}>Files ranked by critical and high severity issue count</p>
            </div>
            {heatmap.length === 0 ? <Empty Icon={Shield} msg="No security issues found — your code looks clean!" /> : (
              <div style={{ padding: 24, display: "flex", flexDirection: "column", gap: 16 }}>
                {heatmap.map((item, i) => {
                  const maxTotal = heatmap[0]?.total || 1;
                  const critW = Math.min((item.critical / maxTotal) * 100, 100);
                  const highW = Math.min((item.high / maxTotal) * 100, 100);
                  return (
                    <div key={item.filename}>
                      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 8 }}>
                        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
                          <span style={{ fontSize: 11, color: C.textFaint, fontFamily: "'Outfit', sans-serif", fontWeight: 700, minWidth: 20 }}>#{i + 1}</span>
                          <code style={{ fontSize: 13, color: C.textMid, fontFamily: "monospace" }}>{item.filename}</code>
                        </div>
                        <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                          {item.critical > 0 && <Pill color={C.red} bg={C.redDim}>{item.critical} critical</Pill>}
                          {item.high > 0 && <Pill color={C.orange} bg={C.orangeDim}>{item.high} high</Pill>}
                          <span style={{ fontSize: 11, color: C.textFaint, marginLeft: 4 }}>{item.total} total</span>
                        </div>
                      </div>
                      <div style={{ display: "flex", gap: 3, height: 8, borderRadius: 8, overflow: "hidden", background: "rgba(255,255,255,0.04)", marginLeft: 32 }}>
                        {critW > 0 && <div style={{ width: `${critW}%`, background: C.red, borderRadius: 8, boxShadow: `0 0 8px ${C.red}60`, transition: "width 0.8s ease" }} />}
                        {highW > 0 && <div style={{ width: `${highW}%`, background: C.orange, borderRadius: 8, transition: "width 0.8s ease" }} />}
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        )}

        {/* ── Repositories ── */}
        {tab === "repos" && (
          <div style={{ display: "flex", flexDirection: "column", gap: 20 }} className="fade-up">

            {/* Connected repos */}
            <div style={{ background: C.surface, border: `1px solid ${C.border}`, borderRadius: 20, overflow: "hidden" }}>
              <div style={{ padding: "20px 24px", borderBottom: `1px solid ${C.border}`, display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                <div>
                  <h2 style={{ fontFamily: "'Outfit', sans-serif", fontWeight: 700, fontSize: 17, margin: 0 }}>Connected Repositories</h2>
                  <p style={{ color: C.textDim, fontSize: 13, marginTop: 3 }}>Repos where CodeSentinel is actively reviewing PRs</p>
                </div>
                <Pill color={C.accent} bg={C.accentDim}>{connectedRepos.length} active</Pill>
              </div>
              {connectedRepos.length === 0 ? (
                <Empty Icon={Code2} msg="No repos connected yet — connect one below" />
              ) : (
                <div style={{ padding: 16, display: "flex", flexDirection: "column", gap: 10 }}>
                  {connectedRepos.map((repo: any) => (
                    <div key={repo.id} style={{
                      display: "flex", alignItems: "center", justifyContent: "space-between",
                      padding: "14px 16px", borderRadius: 14,
                      background: C.accentDim, border: `1px solid ${C.accent}20`,
                    }}>
                      <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
                        <div style={{ width: 36, height: 36, borderRadius: 10, background: C.accentDim, display: "flex", alignItems: "center", justifyContent: "center" }}>
                          <Shield size={16} color={C.accent} />
                        </div>
                        <div>
                          <p style={{ fontWeight: 600, fontSize: 14, margin: 0, color: C.text }}>{repo.full_name}</p>
                          <p style={{ fontSize: 12, color: C.textDim, marginTop: 2 }}>
                            {repo.language && <span style={{ marginRight: 12 }}>⬡ {repo.language}</span>}
                            {repo.total_reviews} PR{repo.total_reviews !== 1 ? "s" : ""} reviewed
                          </p>
                        </div>
                      </div>
                      <Pill color={C.accent} bg="rgba(0,255,136,0.08)">✓ Active</Pill>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Available repos */}
            <div style={{ background: C.surface, border: `1px solid ${C.border}`, borderRadius: 20, overflow: "hidden" }}>
              <div style={{ padding: "20px 24px", borderBottom: `1px solid ${C.border}` }}>
                <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 14 }}>
                  <div>
                    <h2 style={{ fontFamily: "'Outfit', sans-serif", fontWeight: 700, fontSize: 17, margin: 0 }}>Available Repositories</h2>
                    <p style={{ color: C.textDim, fontSize: 13, marginTop: 3 }}>Your GitHub repos — click Connect to enable AI reviews</p>
                  </div>
                  <Pill color={C.textMid} bg={C.textFaint}>{availableRepos.length} repos</Pill>
                </div>
                <input
                  value={repoSearch}
                  onChange={e => setRepoSearch(e.target.value)}
                  placeholder="Search repositories..."
                  style={{
                    width: "100%", background: C.bg, border: `1px solid ${C.border}`,
                    borderRadius: 10, padding: "10px 14px", color: C.text,
                    fontSize: 13, outline: "none", fontFamily: "'DM Sans', sans-serif",
                    transition: "border-color 0.2s",
                  }}
                  onFocus={e => (e.target.style.borderColor = C.accent)}
                  onBlur={e => (e.target.style.borderColor = C.border)}
                />
              </div>
              {reposLoading ? (
                <div style={{ display: "flex", alignItems: "center", justifyContent: "center", padding: 48, gap: 12 }}>
                  <div style={{ width: 20, height: 20, borderRadius: "50%", border: `2px solid ${C.border}`, borderTopColor: C.accent, animation: "spin 0.8s linear infinite" }} />
                  <span style={{ color: C.textDim, fontSize: 13 }}>Loading your repositories...</span>
                  <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
                </div>
              ) : availableRepos.length === 0 ? (
                <Empty Icon={GitPullRequest} msg="No repositories found" />
              ) : (
                <div style={{ padding: 16, display: "flex", flexDirection: "column", gap: 8, maxHeight: 480, overflowY: "auto" }}>
                  {availableRepos
                    .filter(r => r.full_name.toLowerCase().includes(repoSearch.toLowerCase()))
                    .map((repo: any) => {
                      const isConnected = connectedRepos.some((c: any) => c.full_name === repo.full_name);
                      const isConnecting = connectingRepo === repo.full_name;
                      return (
                        <RepoRow
                          key={repo.full_name}
                          repo={repo}
                          isConnected={isConnected}
                          isConnecting={isConnecting}
                          onConnect={() => connectRepo(repo)}
                        />
                      );
                    })}
                </div>
              )}
            </div>

            {/* Install hint */}
            <div style={{ background: C.surface, border: `1px solid ${C.border}`, borderRadius: 20, padding: 24 }}>
              <div style={{ display: "flex", alignItems: "flex-start", gap: 16 }}>
                <div style={{ width: 40, height: 40, borderRadius: 12, background: C.blueDim, display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0 }}>
                  <Zap size={18} color={C.blue} />
                </div>
                <div>
                  <h3 style={{ fontFamily: "'Outfit', sans-serif", fontWeight: 700, fontSize: 15, margin: "0 0 6px 0" }}>Don't see your repo?</h3>
                  <p style={{ color: C.textDim, fontSize: 13, lineHeight: 1.6, margin: "0 0 14px 0" }}>
                    Make sure the CodeSentinel GitHub App is installed on your account and granted access to your repositories.
                  </p>
                  <a href="https://github.com/apps" target="_blank" rel="noopener noreferrer"
                    style={{ display: "inline-flex", alignItems: "center", gap: 6, background: C.blue, color: "#fff", borderRadius: 10, padding: "9px 16px", fontSize: 13, fontWeight: 600, cursor: "pointer", textDecoration: "none", fontFamily: "'DM Sans', sans-serif" }}>
                    <Shield size={14} /> Install GitHub App →
                  </a>
                </div>
              </div>
            </div>
          </div>
        )}

      </div>
    </div>
  );
}