# CyberShield RSA — front-end only

No backend, no database, no build step. Just three static files.

## Run
Open `index.html` in a browser, or serve the folder with any static host
(GitHub Pages, Netlify, Cloudflare Pages, `python -m http.server 5500`).

## What changed from the backend version
| Tool | Before | Now |
|---|---|---|
| URL scanner | Google Safe Browsing via server key | Local link analysis (look-alike brands, shorteners, IP hosts, punycode, risky endings…). Optional: user pastes their own Safe Browsing key, stored in their browser |
| Scam message / email | FastAPI rules | Same rules, now in the browser, plus link and sender-domain checks |
| Phone numbers | Shared SQLite community reports | Truecaller-style **caller ID lookup**: personal caller book (names + labels), a static `community-numbers.json` you maintain, number-type info, import/export, share-a-report |
| Password | Browser | Browser, now with improvement tips |

## Fixes along the way
- Email placeholder showed a literal `\n`.
- Phone categories rendered as `[object Object]`.
- Theme toggle was unreachable on mobile; it is now in the mobile menu.
- Theme follows the system preference on first visit.
- A Content-Security-Policy meta tag limits network calls to Google Safe Browsing.

## Limits to be honest about
- Without a server there is no shared community phone database and no secret API key. Anything in front-end code is visible to visitors, so only ever use a Safe Browsing key the visitor supplies, or one restricted to your domain.
- Local link analysis spots patterns, not known-bad sites. A low result is never a guarantee of safety.
- Text review is rule-based, not AI.

## Caller ID: what it can and cannot do
It cannot see incoming calls, read contacts or block calls: only a native Android/iOS app can. Users type or paste the number that called them. To grow the community list, collect reports (the Share button sends a pre-formatted text), verify them, and add them to `community-numbers.json`. Only add numbers you have verified.

## Install as an app
Served over HTTPS, the site is installable (Add to Home Screen) and works offline via `sw.js`.

## UI notes
- All icons are inline SVG (sprite in `index.html`); no emoji or symbol characters.
- Results are colour-coded: red DANGER / red SUSPICIOUS, amber CAUTION, green no warning signs.
- The viewport is locked (no pinch zoom, 16px inputs so iOS never auto-zooms) and hover effects no longer scale or move elements.
- The mobile menu closes after choosing a link, tapping outside, pressing Escape or resizing to desktop.
