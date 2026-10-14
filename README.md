# WebRTC Leak Detector

Browser-side library and demo that gathers [ICE](https://developer.mozilla.org/en-US/docs/Web/API/WebRTC_API/Connectivity) candidates via `RTCPeerConnection`, classifies candidate types and addresses, and compares public candidates against an optional HTTP egress IP.

Private, link-local, and mDNS (`.local`) addresses are listed for inspection. They are **not** treated as a public IP leak.

> **Live demo:** [https://www.kindproxy.com/webrtc-leak-test/](https://www.kindproxy.com/webrtc-leak-test?spread=github)

This repository is provider-independent. The live demo above is a hosted instance; you can self-host `index.html` or import the modules elsewhere.

## Features

- Parse ICE candidate lines (`host`, `srflx`, `prflx`, `relay`)
- Classify addresses: `public`, `private`, `mdns`, `ignored`, …
- Optional comparison against an HTTP egress IP you supply
- Cautious verdicts (mismatch ≠ proof of a “real IP” leak)
- Zero build step — plain ES modules

## Quick start

ES modules require `http://` or `https://` (not `file://`):

```bash
python -m http.server 8080
# or: npx --yes serve -l 8080
```

Open `http://localhost:8080`.

## Browser support

Requires a browser with `RTCPeerConnection` (current Chrome, Firefox, Safari, Edge).

| Environment | Notes |
|-------------|--------|
| Desktop browsers | Supported when WebRTC is enabled |
| Mobile browsers | Usually supported; results vary by OS WebRTC stack |
| WebRTC disabled / blocked | Often yields `no_candidates` |
| No `RTCPeerConnection` | `unsupported` |
| Node.js | Parsing/classification work in tests; gathering needs a browser |

Prefer `localhost` or HTTPS. Some browsers restrict WebRTC on insecure remote origins.

## Network activity and privacy

This tool is **not fully offline**.

1. **STUN (ICE gathering)** — `gatherIceCandidates` / `runLeakTest` create an `RTCPeerConnection` with STUN by default (`stun:stun.l.google.com:19302`). That contact can reveal your network mapping to the STUN operator. Override with `iceServers`.
2. **Optional HTTP IP lookup** — not part of the core API. The demo page may call a third-party API (`api.ipify.org`) to obtain an egress IP for comparison. Pass your own `httpEgressIp`, use “Run without IP lookup” in the demo, or skip lookup entirely.
3. **Local processing** — parsing, classification, and verdict logic run in the browser (or Node for unit tests).

See [docs/privacy.md](./docs/privacy.md).

## Verdicts

Returned by `analyzeCandidates` / `runLeakTest` as `result.verdict`:

| Verdict | When |
|---------|------|
| `potential_leak` | At least one **public** WebRTC address differs from `httpEgressIp`, **or** public WebRTC addresses were found and no `httpEgressIp` was provided (unverified publics). **Not** definitive proof of a real-IP leak. |
| `no_public_mismatch` | Every distinct public WebRTC address equals `httpEgressIp`. Extra publics (e.g. dual-stack) count as a mismatch. Locals/mDNS may still appear. |
| `local_only` | Candidates present, but no public addresses — private and/or mDNS only. Not a public leak; may still aid fingerprinting. |
| `relay_only` | No public addresses, no `host`/`srflx` candidates, and at least one `relay` candidate. |
| `no_candidates` | Gathering returned nothing (blocked, failed, or timed out). |
| `unsupported` | `RTCPeerConnection` unavailable (`runLeakTest` only). |

### How to read `potential_leak`

Treat it as a **signal to investigate**, not a conviction:

- Dual-stack IPv4/IPv6 and multiple interfaces can produce several legitimate public addresses.
- CGNAT and carrier middleboxes can disagree with a simple HTTP lookup.
- VPN/proxy egress may differ from what STUN observes by design.
- Without `httpEgressIp`, any public candidate is flagged as unverified (`mismatchedPublicIps` lists all publics).

Compare against the egress IP you **expect** from your VPN or proxy when possible.

## API

### `runLeakTest(options?)` → `Promise<DetectorResult>`

Gathers candidates, then analyzes them. Browser-oriented.

```js
import { runLeakTest } from './src/detector.js'

const result = await runLeakTest({
  // Documentation-net example only — replace with your expected HTTP egress IP
  httpEgressIp: '203.0.113.10', // optional; null/omit = no comparison baseline
  timeoutMs: 4000,              // default 4000
  iceServers: [{ urls: 'stun:stun.l.google.com:19302' }] // optional override
})

console.log(result.verdict)
console.log(result.publicIps, result.mismatchedPublicIps)
console.log(result.candidates)
```

### `gatherIceCandidates(options?)` → `Promise<ParsedIceCandidate[]>`

ICE gathering only. Same `timeoutMs` / `iceServers` options. Resolves to `[]` if WebRTC is unavailable.

### `analyzeCandidates(candidates, httpEgressIp?)` → `DetectorResult`

Pure analysis (usable in Node). `httpEgressIp` defaults to `null`.

### `DetectorResult` fields

| Field | Type | Description |
|-------|------|-------------|
| `verdict` | string | See table above |
| `summary` | string | Short human-readable explanation |
| `candidates` | `ParsedIceCandidate[]` | Parsed ICE candidates |
| `publicIps` | `string[]` | Distinct public addresses from candidates |
| `privateIps` | `string[]` | Distinct addresses classified `private` (RFC1918, link-local, ULA, CGNAT `100.64/10`, etc.). Loopback/`0.0.0.0` are ignored and omitted. |
| `mdnsHostnames` | `string[]` | Distinct `*.local` hostnames |
| `mismatchedPublicIps` | `string[]` | Subset of `publicIps` that do not equal `httpEgressIp` (case-insensitive). If `httpEgressIp` is omitted/`null`, this is a copy of all `publicIps`. |
| `httpEgressIp` | `string \| null` | Comparison baseline you passed in |
| `typeCounts` | `{ host, srflx, prflx, relay, unknown }` | Counts by ICE type |
| `notes` | `string[]` | Limitations / privacy reminders |

Also re-exported from `detector.js`: `parseIceCandidate`, `classifyAddress`.

### Other modules

```js
import {
  parseIceCandidate,
  extractAddressesFromText,
  groupByCandidateType
} from './src/candidate-parser.js'

import {
  classifyAddress,
  groupAddresses,
  isPrivateIp,
  isMdnsHostname,
  isValidIpv4,
  isValidIpv6,
  isIgnoredAddress
} from './src/ip-classifier.js'

import { renderResult, verdictPresentation } from './src/result-renderer.js'
```

`renderResult(rootElement, result)` draws the demo UI into a DOM node.

## Project layout

```
├── index.html                 # Standalone demo
├── LICENSE
├── README.md
├── src/
│   ├── detector.js            # gatherIceCandidates, analyzeCandidates, runLeakTest
│   ├── candidate-parser.js
│   ├── ip-classifier.js
│   └── result-renderer.js
├── tests/
│   ├── candidate-parser.test.js
│   └── ip-classifier.test.js
└── docs/
    ├── how-it-works.md
    └── privacy.md
```

## Tests

Node 18+ (built-in test runner):

```bash
node --test tests/*.test.js
```

## Limitations

- Depends on browser ICE behavior; extensions or policies may hide or alter candidates.
- Default timeout is 4s; slow networks may need a higher `timeoutMs`.
- Address parsing covers common ICE forms, not every exotic SDP edge case.
- Does not validate whether a VPN/proxy is “working” beyond comparing addresses you provide.

## License

[MIT](./LICENSE)
