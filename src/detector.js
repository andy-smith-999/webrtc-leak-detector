/**
 * WebRTC Leak Detector — gather ICE candidates and classify results.
 *
 * Important semantics:
 * - Local / private / mDNS addresses are NOT reported as a public IP leak.
 * - A public IP from WebRTC that differs from the HTTP egress IP is a
 *   *potential* leak — not proof by itself (CGNAT, dual-stack, multiple
 *   interfaces, or expected proxy egress can all produce mismatches).
 */

import { parseIceCandidate, groupByCandidateType } from './candidate-parser.js'
import { classifyAddress, groupAddresses, isIgnoredAddress } from './ip-classifier.js'

/**
 * @typedef {'idle' | 'testing' | 'no_public_mismatch' | 'potential_leak' | 'local_only' | 'relay_only' | 'no_candidates' | 'unsupported'} LeakVerdict
 */

/**
 * @typedef {object} DetectorOptions
 * @property {number} [timeoutMs]
 * @property {RTCIceServer[]} [iceServers]
 * @property {string | null} [httpEgressIp] Visible IP from an HTTP IP lookup (optional).
 */

/**
 * @typedef {object} DetectorResult
 * @property {LeakVerdict} verdict
 * @property {string} summary
 * @property {import('./candidate-parser.js').ParsedIceCandidate[]} candidates
 * @property {string[]} publicIps
 * @property {string[]} privateIps
 * @property {string[]} mdnsHostnames
 * @property {string[]} mismatchedPublicIps Public WebRTC IPs that differ from httpEgressIp
 * @property {string | null} httpEgressIp
 * @property {Record<string, number>} typeCounts
 * @property {string[]} notes
 */

const DEFAULT_STUN = [{ urls: 'stun:stun.l.google.com:19302' }]

/**
 * @param {DetectorOptions} [options]
 * @returns {Promise<import('./candidate-parser.js').ParsedIceCandidate[]>}
 */
export function gatherIceCandidates(options = {}) {
  const timeoutMs = options.timeoutMs ?? 4000
  const iceServers = options.iceServers ?? DEFAULT_STUN

  if (typeof window === 'undefined' || typeof RTCPeerConnection === 'undefined') {
    return Promise.resolve([])
  }

  return new Promise((resolve) => {
    /** @type {Map<string, import('./candidate-parser.js').ParsedIceCandidate>} */
    const byKey = new Map()
    let finished = false
    /** @type {RTCPeerConnection} */
    let pc

    const finish = () => {
      if (finished) return
      finished = true
      try {
        pc.close()
      } catch {
        /* ignore */
      }
      resolve([...byKey.values()])
    }

    try {
      pc = new RTCPeerConnection({ iceServers })
    } catch {
      resolve([])
      return
    }

    const timer = window.setTimeout(finish, timeoutMs)

    pc.onicecandidate = (event) => {
      if (!event.candidate) {
        window.clearTimeout(timer)
        window.setTimeout(finish, 250)
        return
      }

      const line = event.candidate.candidate
      if (!line) return

      const parsed = parseIceCandidate(line)
      if (!parsed || isIgnoredAddress(parsed.address)) return

      const key = `${parsed.type}|${parsed.protocol}|${parsed.address}|${parsed.port}`
      byKey.set(key, parsed)
    }

    try {
      pc.createDataChannel('webrtc-leak-detector')
      pc.createOffer()
        .then((offer) => pc.setLocalDescription(offer))
        .catch(() => {
          window.clearTimeout(timer)
          finish()
        })
    } catch {
      window.clearTimeout(timer)
      finish()
    }
  })
}

/**
 * @param {import('./candidate-parser.js').ParsedIceCandidate[]} candidates
 * @param {string | null} [httpEgressIp]
 * @returns {DetectorResult}
 */
export function analyzeCandidates(candidates, httpEgressIp = null) {
  const addresses = candidates.map((c) => c.address)
  const grouped = groupAddresses(addresses)
  const byType = groupByCandidateType(candidates)

  const typeCounts = {
    host: byType.host.length,
    srflx: byType.srflx.length,
    prflx: byType.prflx.length,
    relay: byType.relay.length,
    unknown: byType.unknown.length
  }

  const normalizedEgress = httpEgressIp ? String(httpEgressIp).toLowerCase() : null
  const mismatchedPublicIps = normalizedEgress
    ? grouped.public.filter((ip) => ip.toLowerCase() !== normalizedEgress)
    : [...grouped.public]

  /** @type {string[]} */
  const notes = [
    'Private, link-local, and mDNS (.local) addresses are listed for transparency; they alone are not a public IP leak.',
    'A public IP mismatch is a potential signal only — compare against your expected VPN/proxy egress when possible.',
    'This test contacts a STUN server during ICE gathering. Optional HTTP IP lookup uses a separate network request.'
  ]

  /** @type {LeakVerdict} */
  let verdict
  /** @type {string} */
  let summary

  if (candidates.length === 0) {
    verdict = 'no_candidates'
    summary =
      'No ICE candidates were gathered. The browser may block WebRTC, or gathering timed out.'
  } else if (mismatchedPublicIps.length > 0) {
    verdict = 'potential_leak'
    summary =
      'Potential WebRTC leak: WebRTC exposed one or more public IPs that differ from the HTTP egress IP (or no egress IP was provided for comparison).'
  } else if (
    grouped.public.length === 0 &&
    typeCounts.relay > 0 &&
    typeCounts.host === 0 &&
    typeCounts.srflx === 0
  ) {
    verdict = 'relay_only'
    summary =
      'Only relay candidates were observed. Traffic appears to go through a TURN-style path; no public host/srflx IP mismatch was found.'
  } else if (grouped.public.length === 0) {
    verdict = 'local_only'
    summary =
      'WebRTC exposed local/private or mDNS addresses only. This is not classified as a public IP leak, but may still aid network fingerprinting.'
  } else {
    verdict = 'no_public_mismatch'
    summary =
      'No public IP mismatch detected between WebRTC candidates and the HTTP egress IP.'
  }

  // If we have public IPs matching egress only, keep no_public_mismatch even if locals exist
  if (
    verdict === 'potential_leak' &&
    normalizedEgress &&
    mismatchedPublicIps.length === 0
  ) {
    verdict = 'no_public_mismatch'
    summary =
      'No public IP mismatch detected between WebRTC candidates and the HTTP egress IP.'
  }

  return {
    verdict,
    summary,
    candidates,
    publicIps: grouped.public,
    privateIps: grouped.private,
    mdnsHostnames: grouped.mdns,
    mismatchedPublicIps,
    httpEgressIp: httpEgressIp,
    typeCounts,
    notes
  }
}

/**
 * Run a full gather + analyze pass.
 * @param {DetectorOptions} [options]
 * @returns {Promise<DetectorResult>}
 */
export async function runLeakTest(options = {}) {
  if (typeof window === 'undefined' || typeof RTCPeerConnection === 'undefined') {
    return {
      verdict: 'unsupported',
      summary: 'WebRTC (RTCPeerConnection) is not available in this environment.',
      candidates: [],
      publicIps: [],
      privateIps: [],
      mdnsHostnames: [],
      mismatchedPublicIps: [],
      httpEgressIp: options.httpEgressIp ?? null,
      typeCounts: { host: 0, srflx: 0, prflx: 0, relay: 0, unknown: 0 },
      notes: ['This environment does not support the WebRTC APIs required for the test.']
    }
  }

  const candidates = await gatherIceCandidates(options)
  return analyzeCandidates(candidates, options.httpEgressIp ?? null)
}

export { classifyAddress, parseIceCandidate }
