# Pearlynk

**Phishing & Malicious URL Early-Warning System**

A Manifest V3 Chrome extension that performs deterministic, fully-local heuristic risk analysis on URLs. No API keys. No backend. No data leaves your browser.

## Features

- **Instant Risk Scoring** — Paste any URL or analyze the active tab. Get a 0–100 risk score with a clear Safe / Suspicious / High Risk verdict in milliseconds.
- **Explainable Signals** — Every point is accounted for. See whether a domain uses HTTP, a raw IP, punycode, suspicious TLDs, obfuscation patterns, or resembles a trusted brand.
- **Fully Offline** — All analysis runs locally in the browser. Zero network requests. Zero external dependencies.
- **Privacy First** — History is stored in Chrome's local storage. No tracking, no telemetry, no data transmission.
- **Auto-Check Mode** — Optionally analyze every page you visit. The toolbar badge updates with a live risk score as you browse.
- **Deterministic** — The same URL always produces the same score. No black-box AI or hidden logic.

## Technologies

- Chrome Extension Manifest V3
- Vanilla JavaScript (ES2020+)
- HTML5 / CSS3
- Chrome Storage API
- Service Worker (background)

## Installation

1. Clone or download this repository
2. Open Chrome and navigate to `chrome://extensions/`
3. Enable **Developer mode** (top-right toggle)
4. Click **Load unpacked**
5. Select the `pearlynk` folder (the one containing `manifest.json`)
6. Pin the Pearlynk icon to your toolbar

## How Scoring Works

Pearlynk evaluates each URL across multiple heuristic signals and assigns a 0–100 risk score.

| Signal | Impact |
|--------|--------|
| HTTP (not HTTPS) | +8 |
| Raw IP host | +45 |
| Excessive subdomains (>4 levels) | +10 |
| Long URL (>200 characters) | +10 |
| Suspicious keywords (login, verify, secure, etc.) | up to +25 |
| Punycode / xn-- domain | +20 |
| Obfuscation (@ symbol, percent-encoding, non-ASCII) | +15 |
| Lookalike / typosquatting domain | +25 |
| Suspicious TLD (.xyz, .top, .tk, .buzz, etc.) | +15 |
| Encoded redirect in query parameters | +20 |
| Multiple risk signals combined (≥3) | +10 |

### Verdicts

| Score Range | Verdict |
|-------------|---------|
| 0–30 | ✅ Safe |
| 31–69 | ⚠️ Suspicious |
| 70–100 | 🔴 High Risk |

## Project Structure

```
pearlynk/
├── manifest.json          # Chrome extension manifest (V3)
├── background.js          # Service worker — tab updates, messaging, badge
├── src/
│   └── engine.js          # Deterministic URL risk scoring engine
├── popup/
│   ├── popup.html         # Extension popup UI
│   ├── popup.css          # Popup styles (dark navy theme)
│   └── popup.js           # Popup logic — analysis, history, rendering
├── options/
│   ├── options.html       # Settings page
│   ├── options.css        # Settings styles
│   └── options.js         # Auto-check toggle logic
├── icons/
│   ├── icon16.png         # Toolbar icon (16×16)
│   ├── icon48.png         # Extensions page icon (48×48)
│   └── icon128.png        # Chrome Web Store icon (128×128)
├── tests/
│   └── engine.test.js     # Unit tests for the scoring engine
├── docs/
│   ├── index.html         # Landing page
│   ├── styles.css         # Landing page styles
│   └── script.js          # Landing page interactions & animations
├── .gitignore
├── LICENSE
└── README.md
```

## Running Tests

The scoring engine has a comprehensive test suite (37 tests):

```bash
node tests/engine.test.js
```

## Demo URLs

These URLs are safe to copy into the extension. Pearlynk only analyzes the URL string — it never visits or executes them.

| URL | Score | Verdict |
|-----|-------|---------|
| `https://www.google.com` | 5 | Safe |
| `http://example.com` | 15 | Safe |
| `http://192.168.1.1` | 40 | Suspicious |
| `https://g00gle.com` | 25 | Safe |
| `https://example.xyz` | 15 | Safe |

## Website

The `docs/` directory contains a premium landing page for the extension. It can be deployed to GitHub Pages or any static hosting.

> **Note:** After pushing to GitHub, update the Install and View Repository button URLs in `docs/index.html` to point to your actual repository. Search for `YOUR_USERNAME` and replace with your GitHub username.

## Limitations

- Heuristic analysis only — cannot guarantee safety
- No real-time threat intelligence feeds
- Lookalike detection uses simple edit distance on a curated brand list
- Does not inspect page content or follow redirects
- Never auto-blocks navigation — warns and explains only

## License

[MIT](LICENSE)

---

Built by **Team Nocturnal**
