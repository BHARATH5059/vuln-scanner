import { createFileRoute } from "@tanstack/react-router";
import { useServerFn } from "@tanstack/react-start";
import { useEffect, useMemo, useState } from "react";
import { runScan, type ScanResult, type Severity } from "@/lib/scanner.functions";

export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { title: "CyberScan — Web Vulnerability Scanner" },
      {
        name: "description",
        content:
          "Scan a website for common vulnerabilities: missing security headers, weak cookies, exposed software versions, and known CVEs.",
      },
      { property: "og:title", content: "CyberScan — Web Vulnerability Scanner" },
      {
        property: "og:description",
        content: "Educational vulnerability scanner for security headers, TLS, and known CVEs.",
      },
    ],
  }),
  component: Index,
});

const SEV_COLORS: Record<Severity, string> = {
  critical: "var(--color-critical)",
  high: "var(--color-high)",
  medium: "var(--color-medium)",
  low: "var(--color-low)",
  info: "var(--color-muted-foreground)",
};

interface HistoryEntry {
  target: string;
  scannedAt: string;
  riskScore: number;
  riskBand: string;
}

function Index() {
  const scan = useServerFn(runScan);
  const [target, setTarget] = useState("example.com");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [history, setHistory] = useState<HistoryEntry[]>([]);

  useEffect(() => {
    try {
      const raw = localStorage.getItem("cyberscan:history");
      if (raw) setHistory(JSON.parse(raw));
    } catch {}
  }, []);

  function pushHistory(r: ScanResult) {
    const entry: HistoryEntry = {
      target: r.target,
      scannedAt: r.scannedAt,
      riskScore: r.riskScore,
      riskBand: r.riskBand,
    };
    const next = [entry, ...history].slice(0, 10);
    setHistory(next);
    try {
      localStorage.setItem("cyberscan:history", JSON.stringify(next));
    } catch {}
  }

  async function onScan(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setResult(null);
    setLoading(true);
    try {
      const r = await scan({ data: { target } });
      setResult(r);
      pushHistory(r);
    } catch (e: any) {
      setError(e?.message ?? "Scan failed");
    } finally {
      setLoading(false);
    }
  }

  function downloadReport() {
    if (!result) return;
    const blob = new Blob([buildReport(result)], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `cyberscan-${new URL(result.finalUrl).hostname}-${Date.now()}.txt`;
    a.click();
    URL.revokeObjectURL(url);
  }

  return (
    <main className="mx-auto max-w-6xl px-4 py-10 sm:px-6 sm:py-14">
      <header className="mb-10 flex flex-wrap items-end justify-between gap-4">
        <div>
          <div className="mb-2 flex items-center gap-2 text-xs uppercase tracking-[0.25em] text-[var(--color-primary)]">
            <span className="inline-block h-2 w-2 rounded-full bg-[var(--color-primary)]" style={{ animation: "pulse-ring 1.6s infinite" }} />
            defensive security · educational
          </div>
          <h1 className="text-3xl sm:text-5xl font-bold">
            Cyber<span className="text-[var(--color-primary)]">Scan</span>
          </h1>
          <p className="mt-2 max-w-xl text-sm text-[var(--color-muted-foreground)]">
            Probe a public website for missing security headers, weak cookies, exposed server versions, and known CVEs from the NVD.
          </p>
        </div>
      </header>

      <form onSubmit={onScan} className="glass rounded-xl p-4 sm:p-6">
        <label className="block text-xs uppercase tracking-widest text-[var(--color-muted-foreground)]">
          Target URL or domain
        </label>
        <div className="mt-3 flex flex-col gap-3 sm:flex-row">
          <div className="relative flex-1">
            <span className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 font-[var(--font-display)] text-[var(--color-primary)]">
              {">"}
            </span>
            <input
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="example.com or https://example.com"
              className="w-full rounded-md border border-[var(--color-border)] bg-[var(--color-background)] py-3 pl-8 pr-3 font-[var(--font-display)] text-sm outline-none focus:border-[var(--color-primary)]"
              autoCapitalize="off"
              autoCorrect="off"
              spellCheck={false}
              required
            />
          </div>
          <button
            type="submit"
            disabled={loading}
            className="glow-primary rounded-md bg-[var(--color-primary)] px-6 py-3 text-sm font-semibold text-[var(--color-primary-foreground)] transition hover:brightness-110 disabled:opacity-50"
          >
            {loading ? "Scanning…" : "Run scan"}
          </button>
        </div>
        {error && <p className="mt-3 text-sm text-[var(--color-critical)]">{error}</p>}
      </form>

      {loading && <ScanningSkeleton />}

      {result && (
        <section className="mt-8 grid gap-6 lg:grid-cols-3">
          <RiskCard result={result} onDownload={downloadReport} />
          <SummaryCard result={result} />
          <TargetCard result={result} />
          <HeadersCard result={result} />
          <CookiesCard result={result} />
          <CvesCard result={result} />
          {result.recommendations.length > 0 && (
            <div className="glass rounded-xl p-5 lg:col-span-3">
              <h3 className="mb-3 text-lg font-semibold">Recommendations</h3>
              <ul className="grid gap-2 text-sm text-[var(--color-muted-foreground)] sm:grid-cols-2">
                {result.recommendations.map((r, i) => (
                  <li key={i} className="flex gap-2">
                    <span className="text-[var(--color-accent)]">→</span>
                    <span>{r}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </section>
      )}

      {history.length > 0 && (
        <section className="mt-10">
          <h3 className="mb-3 text-sm uppercase tracking-widest text-[var(--color-muted-foreground)]">
            Recent scans
          </h3>
          <div className="glass overflow-hidden rounded-xl">
            <table className="w-full text-left text-sm">
              <thead className="bg-[var(--color-muted)] text-xs uppercase tracking-wider text-[var(--color-muted-foreground)]">
                <tr>
                  <th className="px-4 py-3">Target</th>
                  <th className="px-4 py-3">When</th>
                  <th className="px-4 py-3">Score</th>
                  <th className="px-4 py-3">Risk</th>
                </tr>
              </thead>
              <tbody>
                {history.map((h, i) => (
                  <tr key={i} className="border-t border-[var(--color-border)]">
                    <td className="px-4 py-3 font-[var(--font-display)]">{h.target}</td>
                    <td className="px-4 py-3 text-[var(--color-muted-foreground)]">
                      {new Date(h.scannedAt).toLocaleString()}
                    </td>
                    <td className="px-4 py-3">{h.riskScore}</td>
                    <td className="px-4 py-3">
                      <RiskBadge band={h.riskBand} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}

      <footer className="mt-12 border-t border-[var(--color-border)] pt-6 text-xs text-[var(--color-muted-foreground)]">
        For educational and defensive use only. Only scan systems you own or have explicit permission to test.
      </footer>
    </main>
  );
}

function ScanningSkeleton() {
  return (
    <div className="scanline scanline-after mt-8 grid gap-4 rounded-xl border border-[var(--color-border)] bg-[var(--color-card)] p-6">
      <div className="font-[var(--font-display)] text-sm text-[var(--color-primary)]">
        ▶ initiating probe…
      </div>
      {["resolving target", "fetching headers", "analyzing TLS", "querying NVD"].map((s) => (
        <div key={s} className="flex items-center gap-3 text-sm text-[var(--color-muted-foreground)]">
          <span className="inline-block h-2 w-2 animate-pulse rounded-full bg-[var(--color-accent)]" />
          {s}
        </div>
      ))}
    </div>
  );
}

function RiskCard({ result, onDownload }: { result: ScanResult; onDownload: () => void }) {
  const max = 150;
  const pct = Math.min(100, (result.riskScore / max) * 100);
  const color =
    result.riskBand === "Safe"
      ? "var(--color-safe)"
      : result.riskBand === "Moderate"
        ? "var(--color-medium)"
        : result.riskBand === "High Risk"
          ? "var(--color-high)"
          : "var(--color-critical)";
  return (
    <div className="glass rounded-xl p-5">
      <h3 className="text-sm uppercase tracking-widest text-[var(--color-muted-foreground)]">
        Risk Score
      </h3>
      <div className="mt-3 flex items-end gap-3">
        <div className="font-[var(--font-display)] text-5xl font-bold" style={{ color }}>
          {result.riskScore}
        </div>
        <RiskBadge band={result.riskBand} />
      </div>
      <div className="mt-4 h-2 overflow-hidden rounded-full bg-[var(--color-muted)]">
        <div className="h-full transition-all" style={{ width: `${pct}%`, background: color }} />
      </div>
      <button
        onClick={onDownload}
        className="mt-5 w-full rounded-md border border-[var(--color-border)] bg-[var(--color-background)] px-4 py-2 text-sm font-medium hover:border-[var(--color-primary)]"
      >
        ↓ Download report
      </button>
    </div>
  );
}

function RiskBadge({ band }: { band: string }) {
  const color =
    band === "Safe"
      ? "var(--color-safe)"
      : band === "Moderate"
        ? "var(--color-medium)"
        : band === "High Risk"
          ? "var(--color-high)"
          : "var(--color-critical)";
  return (
    <span
      className="rounded-full border px-2.5 py-0.5 text-xs font-semibold uppercase tracking-wider"
      style={{ color, borderColor: color }}
    >
      {band}
    </span>
  );
}

function SummaryCard({ result }: { result: ScanResult }) {
  const items: { key: Severity; label: string }[] = [
    { key: "critical", label: "Critical" },
    { key: "high", label: "High" },
    { key: "medium", label: "Medium" },
    { key: "low", label: "Low" },
  ];
  return (
    <div className="glass rounded-xl p-5">
      <h3 className="text-sm uppercase tracking-widest text-[var(--color-muted-foreground)]">
        Findings
      </h3>
      <div className="mt-4 grid grid-cols-2 gap-3">
        {items.map((it) => (
          <div key={it.key} className="rounded-lg border border-[var(--color-border)] p-3">
            <div className="text-xs uppercase tracking-wider" style={{ color: SEV_COLORS[it.key] }}>
              {it.label}
            </div>
            <div className="mt-1 font-[var(--font-display)] text-2xl font-bold">
              {result.summary[it.key]}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

function TargetCard({ result }: { result: ScanResult }) {
  return (
    <div className="glass rounded-xl p-5">
      <h3 className="text-sm uppercase tracking-widest text-[var(--color-muted-foreground)]">
        Target
      </h3>
      <dl className="mt-3 grid gap-2 text-sm">
        <Row k="URL" v={result.finalUrl} mono />
        <Row k="Status" v={String(result.status || "—")} />
        <Row k="Protocol" v={result.tls.protocol?.toUpperCase() ?? "—"} ok={result.tls.secure} />
        <Row k="Server" v={result.server.raw ?? "hidden"} mono />
        <Row k="X-Powered-By" v={result.poweredBy ?? "hidden"} mono />
      </dl>
    </div>
  );
}

function Row({ k, v, mono, ok }: { k: string; v: string; mono?: boolean; ok?: boolean }) {
  return (
    <div className="flex items-start justify-between gap-3 border-b border-dashed border-[var(--color-border)] pb-2 last:border-0">
      <dt className="text-[var(--color-muted-foreground)]">{k}</dt>
      <dd className={`text-right ${mono ? "font-[var(--font-display)]" : ""}`} style={ok != null ? { color: ok ? "var(--color-safe)" : "var(--color-critical)" } : undefined}>
        {v}
      </dd>
    </div>
  );
}

function HeadersCard({ result }: { result: ScanResult }) {
  return (
    <div className="glass rounded-xl p-5 lg:col-span-2">
      <h3 className="mb-3 text-sm uppercase tracking-widest text-[var(--color-muted-foreground)]">
        Security Headers
      </h3>
      <ul className="grid gap-2">
        {result.headers.map((h) => (
          <li
            key={h.name}
            className="flex flex-wrap items-center justify-between gap-2 rounded-md border border-[var(--color-border)] bg-[var(--color-background)]/50 px-3 py-2 text-sm"
          >
            <div className="flex items-center gap-2 font-[var(--font-display)]">
              <span
                className="inline-block h-2 w-2 rounded-full"
                style={{ background: h.present ? "var(--color-safe)" : SEV_COLORS[h.severity] }}
              />
              {h.name}
            </div>
            <div className="flex items-center gap-2 text-xs">
              {h.present ? (
                <span className="max-w-[260px] truncate text-[var(--color-muted-foreground)]" title={h.value ?? ""}>
                  {h.value}
                </span>
              ) : (
                <span className="uppercase tracking-wider" style={{ color: SEV_COLORS[h.severity] }}>
                  missing · {h.severity}
                </span>
              )}
            </div>
          </li>
        ))}
      </ul>
    </div>
  );
}

function CookiesCard({ result }: { result: ScanResult }) {
  if (result.cookies.length === 0) {
    return (
      <div className="glass rounded-xl p-5">
        <h3 className="mb-3 text-sm uppercase tracking-widest text-[var(--color-muted-foreground)]">
          Cookies
        </h3>
        <p className="text-sm text-[var(--color-muted-foreground)]">No Set-Cookie headers observed.</p>
      </div>
    );
  }
  return (
    <div className="glass rounded-xl p-5">
      <h3 className="mb-3 text-sm uppercase tracking-widest text-[var(--color-muted-foreground)]">
        Cookies
      </h3>
      <ul className="grid gap-2 text-sm">
        {result.cookies.map((c) => (
          <li key={c.name} className="rounded-md border border-[var(--color-border)] p-2">
            <div className="font-[var(--font-display)]">{c.name}</div>
            <div className="mt-1 flex flex-wrap gap-2 text-xs">
              <Flag ok={c.secure} label="Secure" />
              <Flag ok={c.httpOnly} label="HttpOnly" />
              <span className="rounded bg-[var(--color-muted)] px-2 py-0.5 text-[var(--color-muted-foreground)]">
                SameSite: {c.sameSite ?? "—"}
              </span>
            </div>
          </li>
        ))}
      </ul>
    </div>
  );
}

function Flag({ ok, label }: { ok: boolean; label: string }) {
  return (
    <span
      className="rounded px-2 py-0.5"
      style={{
        background: ok ? "color-mix(in oklab, var(--color-safe) 18%, transparent)" : "color-mix(in oklab, var(--color-critical) 18%, transparent)",
        color: ok ? "var(--color-safe)" : "var(--color-critical)",
      }}
    >
      {ok ? "✓" : "✗"} {label}
    </span>
  );
}

function CvesCard({ result }: { result: ScanResult }) {
  const sorted = useMemo(() => [...result.cves].sort((a, b) => (b.cvss ?? 0) - (a.cvss ?? 0)), [result.cves]);
  return (
    <div className="glass rounded-xl p-5 lg:col-span-3">
      <h3 className="mb-3 text-sm uppercase tracking-widest text-[var(--color-muted-foreground)]">
        Known CVEs {result.server.product && result.server.version && `· ${result.server.product} ${result.server.version}`}
      </h3>
      {sorted.length === 0 ? (
        <p className="text-sm text-[var(--color-muted-foreground)]">
          {result.server.version
            ? "No CVEs returned from NVD for the detected version."
            : "No software version exposed — CVE lookup skipped."}
        </p>
      ) : (
        <ul className="grid gap-2">
          {sorted.map((c) => (
            <li
              key={c.id}
              className="flex flex-wrap items-start justify-between gap-3 rounded-md border border-[var(--color-border)] bg-[var(--color-background)]/50 p-3"
            >
              <div className="min-w-0 flex-1">
                <a
                  href={c.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="font-[var(--font-display)] text-sm font-semibold hover:text-[var(--color-primary)]"
                >
                  {c.id}
                </a>
                <p className="mt-1 text-xs text-[var(--color-muted-foreground)]">{c.description}</p>
              </div>
              <div className="flex items-center gap-2 text-xs">
                <span
                  className="rounded px-2 py-0.5 font-[var(--font-display)] font-bold"
                  style={{ color: SEV_COLORS[c.severity], borderColor: SEV_COLORS[c.severity], border: "1px solid" }}
                >
                  {c.cvss?.toFixed(1) ?? "—"}
                </span>
                <span className="uppercase tracking-wider" style={{ color: SEV_COLORS[c.severity] }}>
                  {c.severity}
                </span>
              </div>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function buildReport(r: ScanResult): string {
  const line = "=".repeat(60);
  const sev = (n: number, label: string) => `  ${label.padEnd(10)} ${n}`;
  return [
    line,
    "  CyberScan — Vulnerability Report",
    line,
    `Target       : ${r.target}`,
    `Final URL    : ${r.finalUrl}`,
    `Scanned at   : ${r.scannedAt}`,
    `HTTP status  : ${r.status}`,
    `Protocol     : ${r.tls.protocol} (${r.tls.secure ? "secure" : "INSECURE"})`,
    `Server       : ${r.server.raw ?? "hidden"}`,
    `X-Powered-By : ${r.poweredBy ?? "hidden"}`,
    "",
    `RISK SCORE   : ${r.riskScore}  (${r.riskBand})`,
    "",
    "Findings:",
    sev(r.summary.critical, "Critical"),
    sev(r.summary.high, "High"),
    sev(r.summary.medium, "Medium"),
    sev(r.summary.low, "Low"),
    "",
    line,
    "  Security Headers",
    line,
    ...r.headers.map(
      (h) =>
        `[${h.present ? "OK " : "MISS"}] ${h.name.padEnd(28)} ${h.present ? h.value : `(${h.severity}) ${h.recommendation}`}`,
    ),
    "",
    line,
    "  Cookies",
    line,
    ...(r.cookies.length
      ? r.cookies.map((c) => `- ${c.name}  Secure=${c.secure}  HttpOnly=${c.httpOnly}  SameSite=${c.sameSite ?? "—"}`)
      : ["(none)"]),
    "",
    line,
    "  CVEs",
    line,
    ...(r.cves.length
      ? r.cves.map((c) => `- ${c.id}  CVSS=${c.cvss ?? "—"}  ${c.severity}\n  ${c.description}\n  ${c.url}`)
      : ["(none reported)"]),
    "",
    line,
    "  Recommendations",
    line,
    ...r.recommendations.map((s) => `- ${s}`),
    "",
    r.errors.length ? `Errors: ${r.errors.join("; ")}` : "",
    "",
    "Generated by CyberScan — for educational and defensive use only.",
  ].join("\n");
}
