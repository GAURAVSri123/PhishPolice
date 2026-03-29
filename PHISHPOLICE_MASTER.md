# PhishPolice — Complete Technical Reference

> One document covering the idea, architecture, scoring, DNS detection, autonomous blocking, and everything implemented.

---

## 1. Idea & Motivation

PhishPolice is a Chrome extension + Python backend that **autonomously protects users from phishing and malicious websites** as they browse — no button clicks, no manual scans.

The core insight: most phishing detection tools are reactive (you have to ask them to scan). PhishPolice is proactive — it intercepts every navigation, runs a multi-factor analysis in the background, and blocks dangerous pages before the user can interact with them.

Inspired by ISP-level DNS filtering systems (like Airtel's), the project extends that idea to the browser layer with:
- Multi-resolver DNS comparison to detect manipulation
- AI-powered explanations so users understand *why* a site was blocked
- Temporary vs permanent blocks based on risk severity

---

## 2. System Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                        CHROME BROWSER                         │
│                                                               │
│  ┌─────────────────┐        ┌──────────────────────────────┐ │
│  │  Web Page       │◄───────│  Extension                   │ │
│  │  (or blocked)   │        │  background.js  content.js   │ │
│  └─────────────────┘        │  popup.html     popup.js     │ │
│                             └──────────────────────────────┘ │
└──────────────────────────────────────────────────────────────┘
                                        │ HTTP (localhost)
                                        ▼
┌──────────────────────────────────────────────────────────────┐
│                   PHISHPOLICE BACKEND  (Flask)                │
│                                                               │
│  POST /api/analyze          ← full security scan             │
│  POST /api/dns-precheck     ← quick DNS check                │
│  POST /api/explain-block    ← AI block explanation           │
│  GET  /api/health           ← health check                   │
│                                                               │
│  Detection Modules (backend/utils/)                          │
│  ├── dns_blocking.py        DNS manipulation detection       │
│  ├── ssl_check.py           SSL certificate validation       │
│  ├── domain_age.py          WHOIS domain age lookup          │
│  ├── typosquat_scanner.py   Brand impersonation detection    │
│  ├── visual_analysis.py     AI screenshot analysis           │
│  ├── ct_monitor.py          Certificate Transparency check   │
│  ├── domain_checks.py       TLD / subdomain analysis         │
│  └── llm_proxy.py           NVIDIA Mistral AI integration    │
└──────────────────────────────────────────────────────────────┘
                                        │ HTTPS
                                        ▼
┌──────────────────────────────────────────────────────────────┐
│              NVIDIA AI API  (Mistral Small 3.1 24B)           │
│  • Phishing analysis summary                                  │
│  • Block explanation generation                               │
└──────────────────────────────────────────────────────────────┘
```

### Extension Files

| File | Role |
|------|------|
| `background.js` | Service worker — navigation listener, autonomous scan, blocking logic |
| `content.js` | Injected into pages — extracts forms, DOM, patterns |
| `popup.html/js` | Extension popup — shows scan results, history |
| `manifest.json` | Permissions: `scripting`, `tabs`, `storage`, `webNavigation`, `activeTab` |

### Backend Files

| File | Role |
|------|------|
| `app.py` | Flask app, all API endpoints, risk score aggregation |
| `utils/dns_blocking.py` | DNS multi-resolver comparison, blocking detection |
| `utils/ssl_check.py` | SSL certificate validity, expiry, self-signed check |
| `utils/domain_age.py` | WHOIS lookup for domain registration age |
| `utils/typosquat_scanner.py` | Levenshtein/fuzzy match against known brands |
| `utils/visual_analysis.py` | Screenshot → Mistral vision model for brand impersonation |
| `utils/ct_monitor.py` | Certificate Transparency log queries |
| `utils/domain_checks.py` | TLD risk, subdomain analysis, IP-as-hostname |
| `utils/llm_proxy.py` | NVIDIA API wrapper for Mistral AI calls |

---

## 3. Autonomous Scanning Flow

Every page navigation triggers this pipeline automatically — no user interaction needed.

```
User navigates to site
        │
        ▼
webNavigation.onBeforeNavigate fires
        │
        ├─ Is hostname whitelisted? → YES → Allow, done
        │
        ▼
Check block records (chrome.storage)
        │
        ├─ Already blocked (not expired)? → YES → Show block page immediately
        │
        ▼
Wait 1.5s for page to load
        │
        ▼
Inject content.js → extract features
  • URL, hostname, title
  • All forms (action, method, password fields, external submit)
  • DOM signature (first 200 elements)
  • Suspicious patterns (urgency text, hidden iframes)
  • External link ratio
        │
        ▼
Capture screenshot (tabs.captureVisibleTab)
        │
        ▼
POST /api/analyze  →  Backend runs all detection modules
        │
        ▼
Receive { verdict, score, evidence, llm_analysis, dns_info, ... }
        │
        ├─ score < 0.25 → Allow, clear badge, store result
        │
        ▼
score ≥ 0.25 → BLOCK
        │
        ├─ Store block record (temporary or permanent)
        ├─ POST /api/explain-block → get AI explanation
        └─ Inject blocking page HTML into tab
```

### Whitelisted Domains (not scanned)

```javascript
const safeDomains = [
  "google.com", "youtube.com", "github.com",
  "stackoverflow.com", "localhost"
];
```

---

## 4. Risk Scoring System

The backend aggregates scores from 8 independent modules. All scores are capped and summed, then clamped to `[0.00, 0.99]`.

### Score Components

| Module | Max Contribution | Key Signals |
|--------|-----------------|-------------|
| Typosquatting | 0.25 | Fuzzy match against brand names (PayPal, Google, etc.) |
| Domain Age | 0.20 | < 30 days → 0.20, < 90 days → 0.10, > 1 year → 0.00 |
| Visual Analysis | 0.20 | AI detects brand logo impersonation in screenshot |
| DNS Blocking | 0.15 | DNS manipulation, localhost redirect, NXDOMAIN |
| SSL Certificate | 0.12 | No SSL, expired, self-signed, low security score |
| Forms | 0.15 | Password fields, external form submission |
| CT Monitor | 0.08 | No certs in transparency logs |
| Domain Flags | 0.08 | Suspicious TLD (.tk, .xyz), IP-as-hostname, many subdomains |
| DOM Behavior | 0.10 | Hidden iframes, urgency language, high external link ratio |

### DNS Blocking Sub-scores

| Blocking Type | Risk Added | Confidence |
|---------------|-----------|------------|
| Localhost redirect (127.x) | 0.15 | 90% |
| DNS hijack (private IP) | 0.10–0.15 | 75% |
| NXDOMAIN (ISP blocks, public resolves) | 0.08 | 70% |
| ISP filter (known blocking IP) | 0.02–0.05 | 85% |
| Transparent proxy detected | +0.03 | varies |
| Low TTL (< 60s) | +0.03 | 40% |

### Verdict Thresholds

```
score ≥ 0.55  →  "phish"       (PERMANENT block)
score ≥ 0.25  →  "suspicious"  (TEMPORARY block, 5 minutes)
score < 0.25  →  "safe"        (allow)
```

### Score Calculation (Python)

```python
def calculate_risk_score(...):
    score = 0.0
    score += typosquat_risk      # 0–0.35
    score += domain_age_risk     # 0–0.20
    score += visual_risk         # 0–0.20
    score += dns_blocking_risk   # 0–0.15

    # SSL
    if ssl_security < 30:   score += 0.10
    if not has_ssl:         score += 0.06
    if is_expired:          score += 0.05
    if is_self_signed:      score += 0.05

    score += ct_risk             # 0–0.15

    # Domain flags
    if is_ip_address:       score += 0.05
    if suspicious_tld:      score += 0.04

    # Forms
    if password_forms > 0:  score += 0.06
    if external_forms > 0:  score += 0.08

    # DOM
    if hidden_iframes:      score += 0.04
    if urgency_patterns:    score += min(0.06, count * 0.02)

    return min(round(score, 2), 0.99)
```

---

## 5. DNS Blocking Detection

### Design

The DNS module (`backend/utils/dns_blocking.py`) detects when a domain's DNS resolution is being manipulated by comparing results across multiple resolvers.

**Resolvers queried:**
1. System DNS (ISP-provided, via `socket.getaddrinfo`)
2. Google DNS — 8.8.8.8
3. Cloudflare DNS — 1.1.1.1
4. Quad9 DNS — 9.9.9.9

**Detection logic:**

```
System DNS IPs  vs  Public DNS IPs
        │
        ├─ Identical → No blocking
        ├─ Subset (CDN behavior) → No blocking
        ├─ Same /24 subnet → No blocking (load balancing)
        ├─ Same /16 subnet → No blocking (large CDN)
        ├─ Localhost IP (127.x) → LOCALHOST_REDIRECT (confidence 90)
        ├─ Private IP (10.x, 192.168.x) → DNS_HIJACK (confidence 75)
        ├─ Known blocking IP → ISP_FILTER (confidence 85)
        ├─ NXDOMAIN + public resolves → NXDOMAIN block (confidence 70)
        ├─ Low TTL < 60s → DNS_HIJACK (confidence 40)
        └─ Completely different ranges → DNS_HIJACK (confidence 60)
```

**Transparent proxy detection:**
- HTTP `Via`, `X-Forwarded-For`, `X-Cache` headers
- Compare DNS-resolved IP vs actual TCP connection IP
- HTTP redirect to ISP warning/preview pages

**Caching:** Results cached 5 minutes in `_dns_cache` dict (server-side) and `dnsCache` Map (extension-side).

### Key Data Structures

```python
@dataclass
class DNSBlockingEvidence:
    hostname: str
    blocking_detected: bool
    blocking_type: BlockingType   # NONE | ISP_FILTER | DNS_HIJACK |
                                  # TRANSPARENT_PROXY | NXDOMAIN | LOCALHOST_REDIRECT
    confidence_score: int         # 0–100
    system_dns_result: DNSResult
    public_dns_results: List[DNSResult]
    ip_discrepancies: List[str]
    transparent_proxy_detected: bool
    low_ttl_detected: bool
    details: List[str]            # human-readable evidence strings
```

### API: `/api/dns-precheck`

```
POST /api/dns-precheck
Body:  { "hostname": "example.com" }

Response:
{
  "hostname": "example.com",
  "blocking_detected": false,
  "blocking_type": "none",
  "confidence_score": 0,
  "risk_score": 0.0,
  "transparent_proxy_detected": false,
  "summary": "No DNS blocking detected"
}
```

---

## 6. Backend API Reference

### `POST /api/analyze`

Full security scan. Rate limited: 10/min.

**Request:**
```json
{
  "url": "https://example.com/page",
  "hostname": "example.com",
  "forms": [{ "hasPassword": true, "submitsToDifferentDomain": false }],
  "dom_signature": "DIV#app.container|FORM|INPUT...",
  "suspiciousPatterns": ["urgency: \"verify immediately\""],
  "externalLinks": { "external": 5, "total": 20 },
  "image_b64": "<base64 screenshot>"
}
```

**Response:**
```json
{
  "verdict": "suspicious",
  "score": 0.45,
  "evidence": ["⚠️ Young domain: 45 days old", "✓ SSL valid"],
  "ssl_info": { "has_ssl": true, "is_valid": true, "issuer": "Let's Encrypt" },
  "domain_info": { "is_typosquat": false, "age_days": 45 },
  "dns_info": { "blocking_detected": false, "confidence_score": 0 },
  "llm_analysis": {
    "summary": "Site appears legitimate but is relatively new.",
    "risk_factors": ["New domain"],
    "recommendation": "Proceed with caution"
  }
}
```

### `POST /api/dns-precheck`

Quick DNS check only. Rate limited: 30/min. Returns in < 2 seconds.

### `POST /api/explain-block`

AI explanation for a blocked site. Rate limited: 20/min.

**Request:**
```json
{
  "hostname": "suspicious-site.tk",
  "verdict": "suspicious",
  "score": 0.65,
  "evidence": ["⚠️ Suspicious TLD: .tk", "🚨 New domain: 15 days old"],
  "ssl_info": { "is_valid": false },
  "domain_info": { "age_days": 15 },
  "dns_info": { "blocking_detected": false }
}
```

**Response:**
```json
{
  "hostname": "suspicious-site.tk",
  "explanation": "This site was blocked because it's very new and uses a high-risk domain extension. Proceeding could put your personal information at risk."
}
```

### `GET /api/health`

```json
{
  "status": "healthy",
  "version": "2.3.0",
  "name": "PhishPolice",
  "features": ["ssl_check", "domain_analysis", "domain_age", "llm_analysis",
               "typosquat_scanner", "ct_monitor", "visual_analysis", "dns_blocking"]
}
```

---

## 7. Blocking System

### Block Types

| Risk Score | Verdict | Block Type | Duration |
|------------|---------|------------|----------|
| 0–24% | Safe | No block | — |
| 25–54% | Suspicious | **Temporary** | 5 minutes |
| 55–100% | Phish | **Permanent** | Until cleared |

### Block Record Storage

Stored in `chrome.storage.local` as `block_<hostname>`:

```json
{
  "hostname": "danimesk.com",
  "score": 0.45,
  "verdict": "suspicious",
  "blockedAt": 1711680000000,
  "expiresAt": 1711680300000,
  "isPermanent": false,
  "evidence": ["..."]
}
```

On every navigation, the extension checks this record first. If a valid (non-expired) block exists, the warning page is shown immediately without re-scanning.

### Blocking Page Design

The blocking page is a full-screen HTML page injected via `chrome.scripting.executeScript` (primary) or `chrome.tabs.update` to a `data:text/html` URL (fallback).

**Layout:**
```
┌─────────────────────────────────────────────────────┐
│ 🛡️  BLOCKED BY PHISHPOLICE          PROTECTION ACTIVE│  ← fixed red banner
├─────────────────────────────────────────────────────┤
│                                                     │
│              ⛔  Access Blocked                      │  ← colored header
│           danimesk.com                              │
│                                                     │
│  [45% RISK]  SUSPICIOUS SITE                        │  ← score row
│              ⏱️ TEMPORARILY BLOCKED (5 min)          │
│                                                     │
│  🤖 Why was this blocked?                           │  ← AI explanation
│  ┌─────────────────────────────────────────────┐   │
│  │ This site was blocked because it's very     │   │
│  │ new and shows signs of being tampered with. │   │
│  └─────────────────────────────────────────────┘   │
│                                                     │
│  ▶ 🔍 Technical Details                             │  ← collapsible
│                                                     │
│  [← Go Back]          [Close Tab]                   │
│                                                     │
│         Protected by PhishPolice 🛡️                 │
└─────────────────────────────────────────────────────┘
```

**Color coding:**
- Phish (≥55%): `#c62828` red header
- Suspicious (25–54%): `#e65100` orange header
- Fixed top banner: always `#c62828` red

---

## 8. Extension Popup

The popup no longer has a scan button. It is purely a status display.

**Scan tab:**
- Animated risk score ring (SVG)
- Verdict badge (Safe / Suspicious / Phishing Risk)
- URL display
- Domain age info
- AI analysis summary (Mistral)
- Evidence list
- Auto-updates via `chrome.storage.onChanged` listener

**History tab:**
- Last 10 scans
- Click to view details
- Clear history button

**Footer:**
- "Report Phishing" button only (opens Google Safe Browsing report)

---

## 9. AI Integration

### Model

NVIDIA-hosted **Mistral Small 3.1 24B Instruct** (`mistralai/mistral-small-3.1-24b-instruct-2503`) via `https://integrate.api.nvidia.com/v1/chat/completions`.

### Two AI Calls Per Block

1. **`/api/analyze`** — phishing analysis prompt
   - Receives: URL, SSL info, domain flags, form data, DOM flags
   - Returns: `SUMMARY`, `RISK_FACTORS`, `RECOMMENDATION`
   - Timeout: 10 seconds

2. **`/api/explain-block`** — user-facing block explanation
   - Receives: hostname, verdict, score, key evidence, DNS/domain/SSL info
   - Returns: 2–3 plain-English sentences explaining the block
   - Timeout: 8 seconds
   - Instruction: no jargon, no mention of "PhishPolice" or "AI", focus on user safety

### Fallback

Both calls have graceful fallbacks — if the API is unavailable, rate-limited, or times out, a static explanation is returned and the block still happens.

---

## 10. Configuration Reference

### `extension/background.js`

```javascript
const CONFIG = {
  API_URL: "http://127.0.0.1:5000/api/analyze",
  DNS_PRECHECK_URL: "http://127.0.0.1:5000/api/dns-precheck",
  EXPLAIN_BLOCK_URL: "http://127.0.0.1:5000/api/explain-block",
  REQUEST_TIMEOUT: 45000,          // full scan timeout (ms)
  DNS_PRECHECK_TIMEOUT: 2000,      // DNS check timeout (ms)
  DNS_CACHE_TTL: 300000,           // 5 minutes
  BLOCK_THRESHOLD: 0.25,           // block if score ≥ this
  TEMPORARY_BLOCK_DURATION: 300000,// 5 minutes
  PERMANENT_BLOCK_THRESHOLD: 0.55  // permanent if score ≥ this
};
```

### `backend/utils/dns_blocking.py`

```python
DNS_QUERY_TIMEOUT = 3      # seconds per query
DNS_TOTAL_TIMEOUT = 5      # seconds for all queries
_cache_ttl = 300           # seconds

DEFAULT_DNS_RESOLVERS = [
    ("8.8.8.8", "Google DNS"),
    ("1.1.1.1", "Cloudflare DNS"),
    ("9.9.9.9", "Quad9 DNS")
]
```

### `backend/.env`

```
NVIDIA_API_KEY=nvapi-...
FLASK_DEBUG=false
```

---

## 11. Running the Project

### Start Backend

```bash
# Windows
cd backend
..\myenv\Scripts\activate
python app.py

# Linux/Mac
cd backend
source ../myenv/bin/activate
python app.py
```

Expected output:
```
🛡️ PhishPolice Backend v2.3 starting on 127.0.0.1:5000
   Features: Typosquat, Domain Age, CT Monitor, Visual Analysis, DNS Blocking, NVIDIA AI
 * Running on http://127.0.0.1:5000
```

### Load Extension

1. Go to `chrome://extensions/`
2. Enable Developer mode
3. Click "Load unpacked" → select `extension/` folder
4. PhishPolice icon appears in toolbar

### Verify

```bash
python test_autonomous_blocking.py
```

Expected:
```
✅ Server is healthy!
✅ Success!
AI Explanation: This site was blocked because...
✅ All tests passed!
```

---

## 12. Useful Debug Commands (Browser Console)

```javascript
// View all stored data
chrome.storage.local.get(null, console.log)

// Clear all block records
chrome.storage.local.clear(() => console.log('cleared'))

// Check specific block
chrome.storage.local.get('block_danimesk.com', console.log)

// View last analysis
chrome.storage.local.get('lastAnalysis', console.log)
```

---

## 13. Performance

| Operation | Target | Actual |
|-----------|--------|--------|
| DNS pre-check (cache miss) | < 2s | ~0.5–1s |
| DNS pre-check (cache hit) | < 100ms | < 50ms |
| Full backend analysis | < 45s | ~3–8s |
| AI explanation | < 8s | ~2–4s |
| Block page injection | < 500ms | < 200ms |
| Total: navigate → blocked | < 10s | ~4–8s |

---

## 14. Security & Privacy

- All analysis runs on **localhost** — no data leaves your machine except to the NVIDIA AI API
- DNS queries go to Google/Cloudflare/Quad9 (standard public resolvers)
- Block records stored locally in `chrome.storage.local`
- No telemetry, no analytics, no third-party tracking
- CORS restricted to `chrome-extension://*` origins only
- Rate limiting on all endpoints prevents abuse

---

*PhishPolice — Autonomous Web Protection. Every page. Every time.* 🛡️
