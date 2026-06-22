# CyberScan

A full-stack, web-based vulnerability scanner that performs passive security audits on web targets. It analyzes HTTP security headers, TLS configuration, server banners, cookies, and matches exposed products/versions against the [NVD CVE API](https://nvd.nist.gov/) — then generates a risk-scored report with actionable recommendations.

![CyberScan Preview](public/preview.png)

## Features

- **Passive HTTP scanning** — No intrusive payloads; only reads public response data.
- **Security header audit** — Checks for CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, and more.
- **TLS/HTTPS analysis** — Detects plain-HTTP targets and reports the negotiated protocol.
- **Cookie security** — Flags cookies missing `Secure`, `HttpOnly`, or `SameSite` attributes.
- **Server fingerprinting** — Parses `Server` and `X-Powered-By` headers and hides unnecessary leakage.
- **CVE lookup** — Queries the NVD CVE API for known vulnerabilities in detected server products and versions.
- **Risk scoring** — Aggregates findings into a weighted score with `Safe / Moderate / High Risk / Critical Risk` bands.
- **PDF reporting** — *(ready for integration; see roadmap below)*
- **Dark cyber-themed UI** — Built with Tailwind CSS, shadcn/ui, and Lucide icons.

## Tech Stack

| Layer | Technology |
|-------|------------|
| Frontend | React 19, TypeScript, TanStack Start, TanStack Router, TanStack Query |
| Styling | Tailwind CSS v4, shadcn/ui |
| Backend | TanStack `createServerFn` (typed RPC) running on Cloudflare Workers |
| External API | NVD CVE API v2.0 |
| Package Manager | Bun |
| Build Tool | Vite 7 |

## Quick Start

### Prerequisites

- [Bun](https://bun.sh/) installed (`npm install -g bun`)
- Node.js 20+ (if you prefer `npm`/`pnpm`)

### Install & Run

```bash
# 1. Clone the repository
git clone https://github.com/YOUR_USERNAME/cyberscan.git
cd cyberscan

# 2. Install dependencies
bun install

# 3. Start the development server
bun dev
```

Open [http://localhost:8080](http://localhost:8080) in your browser.

### Build for Production

```bash
bun run build
```

## Usage

1. Enter a target URL or domain (e.g. `example.com` or `https://example.com`).
2. Click **Scan**.
3. Review the findings: headers, cookies, CVE matches, risk score, and recommendations.
4. Export or share the report as needed.

## Example Vulnerability Sources Referenced

The scanner reports and links to authoritative resources for further reading:

- [NVD - National Vulnerability Database](https://nvd.nist.gov/)
- [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
- [Mozilla Web Security Guidelines](https://infosec.mozilla.org/guidelines/web_security)
- [CSP Evaluator](https://csp-evaluator.withgoogle.com/)
- [Security Headers](https://securityheaders.com/)
- [SSL Labs Server Test](https://www.ssllabs.com/ssltest/)

## Project Structure

```text
cyberscan/
├── src/
│   ├── components/ui/       # shadcn/ui components
│   ├── lib/
│   │   └── scanner.functions.ts   # Server-side scan logic + NVD CVE lookup
│   ├── routes/
│   │   ├── __root.tsx       # Root layout
│   │   └── index.tsx        # Home / scanner page
│   ├── router.tsx
│   ├── start.ts
│   └── styles.css
├── public/
├── package.json
├── vite.config.ts
└── tsconfig.json
```

## Roadmap

- [x] HTTP security header audit
- [x] TLS & cookie analysis
- [x] Server fingerprinting + CVE lookup
- [x] Risk scoring and recommendations
- [ ] PDF report generation
- [ ] User authentication & persistent scan history
- [ ] Nmap / port scan integration via backend worker
- [ ] Scheduled / bulk scanning

## Security Notice

CyberScan is a **defensive** scanning tool intended for targets you own or have explicit permission to test. Do not use it against third-party systems without authorization.
