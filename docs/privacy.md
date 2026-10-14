# Privacy

This tool is designed for transparency. It does **not** claim to be fully offline or to “never send any data.”

## What leaves your device

### 1. STUN (required for typical ICE gathering)

The detector creates an `RTCPeerConnection` with a STUN server (demo default: `stun:stun.l.google.com:19302`).

STUN requests can reveal your network address mapping to that STUN operator. Self-host or change `iceServers` if you do not want to use a public STUN service.

### 2. Optional HTTP IP lookup

The demo page may call a third-party HTTP API (default: `https://api.ipify.org`) to learn the IP that websites see over normal HTTP(S). That request includes ordinary browser metadata (User-Agent, etc.) like any other website visit.

You can:

- click **Run without IP lookup**, or
- replace the lookup URL with your own server, or
- call `runLeakTest({ httpEgressIp: null })` / pass a known expected egress IP yourself.

### 3. What stays local

Parsing candidates, classifying addresses, and rendering results all run in the browser. This repository’s core modules do not upload ICE candidate lists to a backend.

## What we do not do

- No analytics beacons in the core modules
- No account requirement
- No storage of results on a remote server (unless *you* add that)

## Recommendations for distributors

If you embed this detector on a product site:

1. Disclose STUN and IP-lookup destinations next to the “Run” button.
2. Prefer first-party IP lookup endpoints you control.
3. Avoid marketing language that promises “100% private” or “fully offline” unless you have removed STUN and all remote lookups.
4. Keep result copy cautious: prefer “Potential WebRTC Leak” over absolute claims.
