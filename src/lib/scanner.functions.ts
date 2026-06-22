import { createServerFn } from "@tanstack/react-start";

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface HeaderFinding {
  name: string;
  present: boolean;
  value: string | null;
  severity: Severity;
  recommendation: string;
}

export interface CveFinding {
  id: string;
  description: string;
  severity: Severity;
  cvss: number | null;
  url: string;
}

export interface ScanResult {
  target: string;
  finalUrl: string;
  scannedAt: string;
  status: number;
  tls: { protocol: string | null; secure: boolean };
  server: { product: string | null; version: string | null; raw: string | null };
  poweredBy: string | null;
  headers: HeaderFinding[];
  cookies: { name: string; secure: boolean; httpOnly: boolean; sameSite: string | null }[];
  cves: CveFinding[];
  riskScore: number;
  riskBand: "Safe" | "Moderate" | "High Risk" | "Critical Risk";
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  recommendations: string[];
  errors: string[];
}

const SECURITY_HEADERS: { name: string; severity: Severity; recommendation: string }[] = [
  { name: "content-security-policy", severity: "high", recommendation: "Define a strict Content-Security-Policy to mitigate XSS." },
  { name: "strict-transport-security", severity: "high", recommendation: "Add HSTS (e.g. max-age=63072000; includeSubDomains; preload)." },
  { name: "x-frame-options", severity: "medium", recommendation: "Set X-Frame-Options: DENY or use CSP frame-ancestors." },
  { name: "x-content-type-options", severity: "medium", recommendation: "Set X-Content-Type-Options: nosniff." },
  { name: "referrer-policy", severity: "low", recommendation: "Set Referrer-Policy (e.g. no-referrer-when-downgrade)." },
  { name: "permissions-policy", severity: "low", recommendation: "Set Permissions-Policy to restrict powerful browser features." },
  { name: "x-xss-protection", severity: "info", recommendation: "Legacy header; modern browsers ignore it. CSP is preferred." },
];

const SEVERITY_POINTS: Record<Severity, number> = {
  critical: 15,
  high: 10,
  medium: 5,
  low: 2,
  info: 0,
};

function normalizeTarget(input: string): string {
  const t = input.trim();
  if (/^https?:\/\//i.test(t)) return t;
  return `https://${t}`;
}

function parseServer(value: string | null): { product: string | null; version: string | null } {
  if (!value) return { product: null, version: null };
  const m = value.match(/^([A-Za-z0-9_\-./]+?)[/ ]([0-9][0-9A-Za-z.\-_]*)/);
  if (m) return { product: m[1], version: m[2] };
  return { product: value.split(/[\s/]/)[0] || null, version: null };
}

function bandFor(score: number): ScanResult["riskBand"] {
  if (score <= 20) return "Safe";
  if (score <= 50) return "Moderate";
  if (score <= 100) return "High Risk";
  return "Critical Risk";
}

function cvssToSeverity(score: number | null): Severity {
  if (score == null) return "info";
  if (score >= 9) return "critical";
  if (score >= 7) return "high";
  if (score >= 4) return "medium";
  if (score > 0) return "low";
  return "info";
}

async function fetchWithTimeout(url: string, init: RequestInit, ms: number): Promise<Response> {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), ms);
  try {
    return await fetch(url, { ...init, signal: ctrl.signal, redirect: "follow" });
  } finally {
    clearTimeout(t);
  }
}

async function lookupCves(product: string, version: string): Promise<CveFinding[]> {
  try {
    const keyword = encodeURIComponent(`${product} ${version}`);
    const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${keyword}&resultsPerPage=10`;
    const res = await fetchWithTimeout(url, { headers: { Accept: "application/json" } }, 12000);
    if (!res.ok) return [];
    const data: any = await res.json();
    const items: CveFinding[] = [];
    for (const v of data.vulnerabilities ?? []) {
      const c = v.cve;
      if (!c) continue;
      const id = c.id as string;
      const desc =
        (c.descriptions ?? []).find((d: any) => d.lang === "en")?.value ??
        (c.descriptions?.[0]?.value ?? "");
      const m =
        c.metrics?.cvssMetricV31?.[0]?.cvssData ??
        c.metrics?.cvssMetricV30?.[0]?.cvssData ??
        c.metrics?.cvssMetricV2?.[0]?.cvssData;
      const score = typeof m?.baseScore === "number" ? m.baseScore : null;
      items.push({
        id,
        description: desc.slice(0, 400),
        cvss: score,
        severity: cvssToSeverity(score),
        url: `https://nvd.nist.gov/vuln/detail/${id}`,
      });
    }
    return items;
  } catch {
    return [];
  }
}

export const runScan = createServerFn({ method: "POST" })
  .inputValidator((input: { target: string }) => {
    if (!input?.target || typeof input.target !== "string") {
      throw new Error("Target is required");
    }
    const t = input.target.trim();
    if (t.length > 253 || !/^[A-Za-z0-9._:\-/?#=&%]+$/.test(t)) {
      throw new Error("Invalid target format");
    }
    return { target: t };
  })
  .handler(async ({ data }): Promise<ScanResult> => {
    const errors: string[] = [];
    const url = normalizeTarget(data.target);
    let parsed: URL;
    try {
      parsed = new URL(url);
    } catch {
      throw new Error("Invalid URL");
    }

    let response: Response | null = null;
    try {
      response = await fetchWithTimeout(
        url,
        { method: "GET", headers: { "User-Agent": "CyberScan/1.0 (defensive-scanner)" } },
        15000,
      );
    } catch (e: any) {
      errors.push(`Request failed: ${e?.message ?? "unknown error"}`);
    }

    const headersRaw: Record<string, string> = {};
    if (response) {
      response.headers.forEach((v, k) => {
        headersRaw[k.toLowerCase()] = v;
      });
    }

    const headerFindings: HeaderFinding[] = SECURITY_HEADERS.map((h) => ({
      name: h.name,
      present: h.name in headersRaw,
      value: headersRaw[h.name] ?? null,
      severity: h.severity,
      recommendation: h.recommendation,
    }));

    const serverRaw = headersRaw["server"] ?? null;
    const poweredBy = headersRaw["x-powered-by"] ?? null;
    const serverParsed = parseServer(serverRaw);

    const setCookie = response?.headers.get("set-cookie");
    const cookies: ScanResult["cookies"] = [];
    if (setCookie) {
      for (const c of setCookie.split(/,(?=[^;]+=)/)) {
        const parts = c.split(";").map((p) => p.trim());
        const [nameVal] = parts;
        const name = nameVal.split("=")[0];
        if (!name) continue;
        const lower = parts.map((p) => p.toLowerCase());
        cookies.push({
          name,
          secure: lower.includes("secure"),
          httpOnly: lower.includes("httponly"),
          sameSite:
            parts.find((p) => p.toLowerCase().startsWith("samesite="))?.split("=")[1] ?? null,
        });
      }
    }

    let cves: CveFinding[] = [];
    if (serverParsed.product && serverParsed.version) {
      cves = await lookupCves(serverParsed.product, serverParsed.version);
    }

    const summary = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    let score = 0;

    for (const h of headerFindings) {
      if (!h.present && h.severity !== "info") {
        summary[h.severity]++;
        score += SEVERITY_POINTS[h.severity];
      }
    }

    if (parsed.protocol !== "https:") {
      summary.high++;
      score += SEVERITY_POINTS.high;
    }

    for (const c of cookies) {
      if (!c.secure) {
        summary.medium++;
        score += SEVERITY_POINTS.medium;
      }
      if (!c.httpOnly) {
        summary.low++;
        score += SEVERITY_POINTS.low;
      }
    }

    for (const v of cves) {
      if (v.severity in summary) {
        (summary as any)[v.severity]++;
        score += SEVERITY_POINTS[v.severity];
      }
    }

    const recommendations: string[] = [];
    if (parsed.protocol !== "https:") recommendations.push("Serve all traffic over HTTPS and redirect HTTP.");
    for (const h of headerFindings) {
      if (!h.present && h.severity !== "info") recommendations.push(h.recommendation);
    }
    if (cookies.some((c) => !c.secure)) recommendations.push("Mark all cookies as Secure.");
    if (cookies.some((c) => !c.httpOnly)) recommendations.push("Mark session cookies as HttpOnly.");
    if (serverRaw) recommendations.push("Hide or minimize the Server response header to avoid leaking version info.");
    if (poweredBy) recommendations.push("Remove the X-Powered-By header.");

    return {
      target: data.target,
      finalUrl: response?.url ?? url,
      scannedAt: new Date().toISOString(),
      status: response?.status ?? 0,
      tls: { protocol: parsed.protocol.replace(":", ""), secure: parsed.protocol === "https:" },
      server: { product: serverParsed.product, version: serverParsed.version, raw: serverRaw },
      poweredBy,
      headers: headerFindings,
      cookies,
      cves,
      riskScore: score,
      riskBand: bandFor(score),
      summary,
      recommendations,
      errors,
    };
  });
