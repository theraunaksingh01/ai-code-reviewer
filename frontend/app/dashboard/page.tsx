"use client";

import { useEffect, useState } from "react";
import { useSearchParams, useRouter } from "next/navigation";
import { Shield, GitPullRequest, AlertTriangle, CheckCircle, XCircle, TrendingUp, Code2, BarChart3, LogOut } from "lucide-react";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Progress } from "@/components/ui/progress";
import {
  LineChart, Line, XAxis, YAxis, CartesianGrid,
  Tooltip, ResponsiveContainer, BarChart, Bar
} from "recharts";
import axios from "axios";

const API = process.env.NEXT_PUBLIC_API_URL;

export default function Dashboard() {
  const searchParams = useSearchParams();
  const router = useRouter();
  const [token, setToken] = useState<string | null>(null);
  const [user, setUser] = useState<any>(null);
  const [overview, setOverview] = useState<any>(null);
  const [reviews, setReviews] = useState<any[]>([]);
  const [heatmap, setHeatmap] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const t = searchParams.get("token") || localStorage.getItem("cs_token");
    if (!t) { router.push("/"); return; }

    localStorage.setItem("cs_token", t);
    setToken(t);

    const headers = { Authorization: `Bearer ${t}` };

    Promise.all([
      axios.get(`${API}/api/auth/me`, { headers }),
      axios.get(`${API}/api/analytics/overview`, { headers }),
      axios.get(`${API}/api/analytics/reviews`, { headers }),
      axios.get(`${API}/api/analytics/security-heatmap`, { headers }),
    ]).then(([userRes, overviewRes, reviewsRes, heatmapRes]) => {
      setUser(userRes.data);
      setOverview(overviewRes.data);
      setReviews(reviewsRes.data);
      setHeatmap(heatmapRes.data);
    }).catch(() => {
      router.push("/");
    }).finally(() => setLoading(false));
  }, []);

  const logout = () => {
    localStorage.removeItem("cs_token");
    router.push("/");
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-[#030303] flex items-center justify-center">
        <div className="text-center">
          <div className="w-12 h-12 rounded-xl bg-green-500 flex items-center justify-center mx-auto mb-4 animate-pulse">
            <Shield className="w-7 h-7 text-black" />
          </div>
          <p className="text-white/40">Loading your dashboard...</p>
        </div>
      </div>
    );
  }

  const scoreChartData = reviews.slice(0, 10).reverse().map((r, i) => ({
    name: `PR #${r.pr_number}`,
    score: r.quality_score,
  }));

  const severityData = reviews.slice(0, 10).reverse().map((r) => ({
    name: `PR #${r.pr_number}`,
    critical: r.critical_count,
    high: r.high_count,
    medium: r.medium_count,
  }));

  const getScoreColor = (score: number) => {
    if (score >= 80) return "text-green-400";
    if (score >= 50) return "text-yellow-400";
    return "text-red-400";
  };

  const getVerdictIcon = (verdict: string) => {
    if (verdict === "APPROVE") return <CheckCircle className="w-4 h-4 text-green-400" />;
    if (verdict === "REQUEST_CHANGES") return <XCircle className="w-4 h-4 text-red-400" />;
    return <AlertTriangle className="w-4 h-4 text-yellow-400" />;
  };

  return (
    <div className="min-h-screen bg-[#030303] text-white">

      {/* Topbar */}
      <nav className="border-b border-white/5 px-6 py-4 flex items-center justify-between backdrop-blur-xl bg-black/40 sticky top-0 z-50">
        <div className="flex items-center gap-2">
          <div className="w-8 h-8 rounded-lg bg-green-500 flex items-center justify-center">
            <Shield className="w-5 h-5 text-black" />
          </div>
          <span className="font-bold text-xl">CodeSentinel</span>
        </div>
        <div className="flex items-center gap-4">
          {user && (
            <div className="flex items-center gap-3">
              <img src={user.avatar_url} className="w-8 h-8 rounded-full border border-white/10" />
              <span className="text-white/60 text-sm">{user.username}</span>
            </div>
          )}
          <Button variant="ghost" size="sm" onClick={logout} className="text-white/40 hover:text-white">
            <LogOut className="w-4 h-4 mr-2" />
            Logout
          </Button>
        </div>
      </nav>

      <div className="max-w-7xl mx-auto px-6 py-10">

        {/* Header */}
        <div className="mb-10">
          <h1 className="text-4xl font-black mb-2">
            Welcome back, <span className="gradient-text">{user?.username}</span>
          </h1>
          <p className="text-white/40">Here's your code quality intelligence overview</p>
        </div>

        {/* Stats Grid */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-10">
          {[
            {
              label: "Total Reviews",
              value: overview?.total_reviews ?? 0,
              icon: <GitPullRequest className="w-5 h-5 text-blue-400" />,
              color: "blue"
            },
            {
              label: "Avg Quality Score",
              value: `${overview?.average_quality_score ?? 0}/100`,
              icon: <TrendingUp className="w-5 h-5 text-green-400" />,
              color: "green"
            },
            {
              label: "Critical Issues",
              value: overview?.total_critical_issues ?? 0,
              icon: <AlertTriangle className="w-5 h-5 text-red-400" />,
              color: "red"
            },
            {
              label: "Repos Connected",
              value: overview?.repos_connected ?? 0,
              icon: <Code2 className="w-5 h-5 text-purple-400" />,
              color: "purple"
            },
          ].map((stat) => (
            <Card key={stat.label}
              className="bg-white/3 border-white/8 p-6 card-hover">
              <div className="flex items-center justify-between mb-3">
                <span className="text-white/40 text-sm">{stat.label}</span>
                {stat.icon}
              </div>
              <div className="text-3xl font-black">{stat.value}</div>
            </Card>
          ))}
        </div>

        {/* Tabs */}
        <Tabs defaultValue="reviews">
          <TabsList className="bg-white/5 border border-white/10 mb-8">
            <TabsTrigger value="reviews" className="data-[state=active]:bg-green-500 data-[state=active]:text-black">
              PR Reviews
            </TabsTrigger>
            <TabsTrigger value="trends" className="data-[state=active]:bg-green-500 data-[state=active]:text-black">
              Quality Trends
            </TabsTrigger>
            <TabsTrigger value="security" className="data-[state=active]:bg-green-500 data-[state=active]:text-black">
              Security Heatmap
            </TabsTrigger>
          </TabsList>

          {/* PR Reviews Tab */}
          <TabsContent value="reviews">
            <Card className="bg-white/3 border-white/8">
              <div className="p-6 border-b border-white/5">
                <h2 className="font-bold text-lg">Recent PR Reviews</h2>
                <p className="text-white/40 text-sm">All pull requests reviewed by CodeSentinel</p>
              </div>
              <div className="divide-y divide-white/5">
                {reviews.length === 0 ? (
                  <div className="p-12 text-center text-white/30">
                    <GitPullRequest className="w-12 h-12 mx-auto mb-4 opacity-30" />
                    <p>No reviews yet — open a PR to get started</p>
                  </div>
                ) : (
                  reviews.map((review) => (
                    <div key={review.id} className="p-5 flex items-center justify-between hover:bg-white/2 transition-colors">
                      <div className="flex items-center gap-4">
                        {getVerdictIcon(review.verdict)}
                        <div>
                          <p className="font-medium text-sm">{review.pr_title}</p>
                          <p className="text-white/30 text-xs mt-0.5">
                            PR #{review.pr_number} by @{review.pr_author} · {new Date(review.reviewed_at).toLocaleDateString()}
                          </p>
                        </div>
                      </div>
                      <div className="flex items-center gap-4">
                        <div className="hidden md:flex items-center gap-2 text-xs">
                          {review.critical_count > 0 && (
                            <Badge className="bg-red-500/10 text-red-400 border-red-500/20">
                              {review.critical_count} critical
                            </Badge>
                          )}
                          {review.high_count > 0 && (
                            <Badge className="bg-orange-500/10 text-orange-400 border-orange-500/20">
                              {review.high_count} high
                            </Badge>
                          )}
                        </div>
                        <div className={`text-2xl font-black ${getScoreColor(review.quality_score)}`}>
                          {review.quality_score}
                        </div>
                      </div>
                    </div>
                  ))
                )}
              </div>
            </Card>
          </TabsContent>

          {/* Trends Tab */}
          <TabsContent value="trends">
            <div className="grid md:grid-cols-2 gap-6">
              <Card className="bg-white/3 border-white/8 p-6">
                <h3 className="font-bold mb-6">Quality Score Trend</h3>
                {scoreChartData.length > 0 ? (
                  <ResponsiveContainer width="100%" height={250}>
                    <LineChart data={scoreChartData}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#ffffff08" />
                      <XAxis dataKey="name" tick={{ fill: "#ffffff30", fontSize: 11 }} />
                      <YAxis domain={[0, 100]} tick={{ fill: "#ffffff30", fontSize: 11 }} />
                      <Tooltip
                        contentStyle={{ background: "#0a0a0a", border: "1px solid #ffffff15", borderRadius: "8px" }}
                        labelStyle={{ color: "#ffffff60" }}
                      />
                      <Line type="monotone" dataKey="score" stroke="#22c55e" strokeWidth={2} dot={{ fill: "#22c55e", r: 4 }} />
                    </LineChart>
                  </ResponsiveContainer>
                ) : (
                  <div className="h-[250px] flex items-center justify-center text-white/20">
                    No data yet
                  </div>
                )}
              </Card>

              <Card className="bg-white/3 border-white/8 p-6">
                <h3 className="font-bold mb-6">Issues by Severity</h3>
                {severityData.length > 0 ? (
                  <ResponsiveContainer width="100%" height={250}>
                    <BarChart data={severityData}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#ffffff08" />
                      <XAxis dataKey="name" tick={{ fill: "#ffffff30", fontSize: 11 }} />
                      <YAxis tick={{ fill: "#ffffff30", fontSize: 11 }} />
                      <Tooltip
                        contentStyle={{ background: "#0a0a0a", border: "1px solid #ffffff15", borderRadius: "8px" }}
                      />
                      <Bar dataKey="critical" fill="#ef4444" radius={[4, 4, 0, 0]} />
                      <Bar dataKey="high" fill="#f97316" radius={[4, 4, 0, 0]} />
                      <Bar dataKey="medium" fill="#eab308" radius={[4, 4, 0, 0]} />
                    </BarChart>
                  </ResponsiveContainer>
                ) : (
                  <div className="h-[250px] flex items-center justify-center text-white/20">
                    No data yet
                  </div>
                )}
              </Card>

              {/* Verdict breakdown */}
              <Card className="bg-white/3 border-white/8 p-6 md:col-span-2">
                <h3 className="font-bold mb-6">PR Verdict Breakdown</h3>
                <div className="grid grid-cols-3 gap-6">
                  {[
                    { label: "Approved", value: overview?.approved_prs ?? 0, color: "green" },
                    { label: "Changes Requested", value: overview?.changes_requested ?? 0, color: "red" },
                    { label: "Total Reviewed", value: overview?.total_reviews ?? 0, color: "blue" },
                  ].map((item) => (
                    <div key={item.label} className="text-center">
                      <div className={`text-5xl font-black mb-2 ${
                        item.color === "green" ? "text-green-400" :
                        item.color === "red" ? "text-red-400" : "text-blue-400"
                      }`}>
                        {item.value}
                      </div>
                      <div className="text-white/40 text-sm">{item.label}</div>
                      <Progress
                        value={overview?.total_reviews ? (item.value / overview.total_reviews) * 100 : 0}
                        className="mt-3 h-1.5"
                      />
                    </div>
                  ))}
                </div>
              </Card>
            </div>
          </TabsContent>

          {/* Security Heatmap Tab */}
          <TabsContent value="security">
            <Card className="bg-white/3 border-white/8">
              <div className="p-6 border-b border-white/5">
                <h2 className="font-bold text-lg">Security Vulnerability Heatmap</h2>
                <p className="text-white/40 text-sm">Files with the most critical and high severity issues</p>
              </div>
              <div className="p-6 space-y-3">
                {heatmap.length === 0 ? (
                  <div className="py-12 text-center text-white/30">
                    <Shield className="w-12 h-12 mx-auto mb-4 opacity-30" />
                    <p>No security issues found — your code looks clean!</p>
                  </div>
                ) : (
                  heatmap.map((item) => (
                    <div key={item.filename} className="flex items-center gap-4">
                      <code className="text-sm text-white/60 w-64 truncate shrink-0">
                        {item.filename}
                      </code>
                      <div className="flex-1 flex items-center gap-2">
                        <div
                          className="h-6 rounded bg-red-500/60"
                          style={{ width: `${Math.min((item.critical / (heatmap[0]?.total || 1)) * 100, 100)}%`, minWidth: item.critical > 0 ? "8px" : "0" }}
                        />
                        <div
                          className="h-6 rounded bg-orange-500/60"
                          style={{ width: `${Math.min((item.high / (heatmap[0]?.total || 1)) * 100, 100)}%`, minWidth: item.high > 0 ? "8px" : "0" }}
                        />
                      </div>
                      <div className="flex gap-2 text-xs shrink-0">
                        {item.critical > 0 && (
                          <Badge className="bg-red-500/10 text-red-400 border-red-500/20">
                            {item.critical} critical
                          </Badge>
                        )}
                        {item.high > 0 && (
                          <Badge className="bg-orange-500/10 text-orange-400 border-orange-500/20">
                            {item.high} high
                          </Badge>
                        )}
                      </div>
                    </div>
                  ))
                )}
              </div>
            </Card>
          </TabsContent>
        </Tabs>
      </div>
    </div>
  );
}