# How it works

## Overview

1. The browser creates an `RTCPeerConnection` with at least one STUN server.
2. A data channel + local SDP offer triggers ICE candidate gathering.
3. Each `onicecandidate` event is parsed into structured fields:
   - candidate type (`host`, `srflx`, `prflx`, `relay`)
   - address / port / protocol
   - address kind (`public`, `private`, `mdns`, …)
4. Optionally, an HTTP IP lookup provides a visible “egress” IP.
5. Results are classified with cautious wording — never claiming certainty from a single mismatch.

## Candidate types

| Type | Meaning |
|------|---------|
| `host` | Local interface address (often private IP or mDNS hostname) |
| `srflx` | Server-reflexive: public mapping learned via STUN |
| `prflx` | Peer-reflexive: learned from connectivity checks |
| `relay` | Relayed via TURN |

## What counts as a potential leak?

A **Potential WebRTC Leak** is reported when WebRTC exposes one or more **public** IPs that differ from the optional HTTP egress IP (or when public WebRTC IPs appear and no egress IP was supplied for comparison).

This is a **signal**, not proof:

- Dual-stack IPv4/IPv6 can produce multiple legitimate public addresses.
- CGNAT and carrier middleboxes can confuse naive comparisons.
- Your VPN/proxy may intentionally present a different egress than STUN observes.
- Always compare against the IP you *expect* your proxy/VPN to use when possible.

## What is NOT a public leak?

- Private RFC1918 / ULA / link-local addresses
- mDNS hostnames (`*.local`) used by modern browsers to hide LAN IPs
- Loopback / unspecified addresses (`127.0.0.1`, `::1`, `0.0.0.0`)

These may still help fingerprint a network environment, so the UI lists them separately under **Local / mDNS Only** when no public mismatch exists.

## Timeouts

Gathering stops when ICE completes (null candidate) or when the timeout (default 4s) fires. Slow networks may need a higher `timeoutMs`.

## Self-hosting tips

- Point `iceServers` at STUN/TURN you operate or trust.
- Replace the demo IP lookup (`api.ipify.org`) with your own endpoint.
- Serve over HTTPS; some browsers restrict WebRTC on insecure origins.
