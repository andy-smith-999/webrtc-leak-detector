/**
 * Parse WebRTC ICE candidate strings into structured fields.
 *
 * Typical form:
 *   candidate:foundation component protocol priority ip port typ type ...
 * Example:
 *   candidate:842163049 1 udp 1677729535 192.168.1.10 54321 typ host
 *   candidate:... 1 udp 41885439 203.0.113.5 9 typ srflx raddr 0.0.0.0 rport 0
 */

import {
  classifyAddress,
  isIgnoredAddress,
  isMdnsHostname,
  isValidIpv4,
  isValidIpv6
} from './ip-classifier.js'

/** @typedef {'host' | 'srflx' | 'prflx' | 'relay' | 'unknown'} IceCandidateType */

/**
 * @typedef {object} ParsedIceCandidate
 * @property {string} raw
 * @property {string} foundation
 * @property {number} component
 * @property {string} protocol
 * @property {number} priority
 * @property {string} address
 * @property {number} port
 * @property {IceCandidateType} type
 * @property {string | null} relatedAddress
 * @property {number | null} relatedPort
 * @property {'ignored' | 'mdns' | 'private' | 'public' | 'hostname' | 'unknown'} addressKind
 */

/** Token-ish matchers; final acceptance uses isValidIpv4 / isValidIpv6 / isMdnsHostname. */
const IPV4_IN_TEXT = /\b(\d{1,3}(?:\.\d{1,3}){3})\b/g
const IPV6_IN_TEXT = /(?:^|[\s\[\]])((?:[a-f0-9]{0,4}:){2,7}[a-f0-9]{0,4}|::(?:[a-f0-9]{1,4}:){0,6}[a-f0-9]{0,4})(?=$|[\s%\]])/gi
const MDNS_IN_TEXT = /\b([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.local|[a-z0-9][\w.-]*\.local)\b/gi

/**
 * @param {string} type
 * @returns {IceCandidateType}
 */
function normalizeType(type) {
  const t = String(type || '').toLowerCase()
  if (t === 'host' || t === 'srflx' || t === 'prflx' || t === 'relay') return t
  return 'unknown'
}

/**
 * @param {string} candidateLine
 * @returns {ParsedIceCandidate | null}
 */
export function parseIceCandidate(candidateLine) {
  if (!candidateLine || typeof candidateLine !== 'string') return null

  const raw = candidateLine.trim()
  // RTCIceCandidate.candidate may already omit the "candidate:" prefix in some browsers
  const line = raw.replace(/^candidate:/i, '').trim()
  const parts = line.split(/\s+/)

  if (parts.length < 8) {
    // Fallback: still try to extract addresses from unstructured text
    const addresses = extractAddressesFromText(raw)
    if (!addresses.length) return null
    const address = addresses[0]
    return {
      raw,
      foundation: '',
      component: 0,
      protocol: '',
      priority: 0,
      address,
      port: 0,
      type: 'unknown',
      relatedAddress: null,
      relatedPort: null,
      addressKind: classifyAddress(address)
    }
  }

  const foundation = parts[0]
  const component = Number(parts[1]) || 0
  const protocol = String(parts[2] || '').toLowerCase()
  const priority = Number(parts[3]) || 0
  const address = parts[4]
  const port = Number(parts[5]) || 0

  let type = 'unknown'
  let relatedAddress = null
  let relatedPort = null

  for (let i = 6; i < parts.length; i++) {
    const token = parts[i].toLowerCase()
    if (token === 'typ' && parts[i + 1]) {
      type = normalizeType(parts[i + 1])
      i++
    } else if (token === 'raddr' && parts[i + 1]) {
      relatedAddress = parts[i + 1]
      i++
    } else if (token === 'rport' && parts[i + 1]) {
      relatedPort = Number(parts[i + 1]) || 0
      i++
    }
  }

  return {
    raw,
    foundation,
    component,
    protocol,
    priority,
    address,
    port,
    type,
    relatedAddress,
    relatedPort,
    addressKind: classifyAddress(address)
  }
}

/**
 * Extract IPv4, IPv6, and mDNS hostnames from free-form candidate text.
 * @param {string} text
 * @returns {string[]}
 */
export function extractAddressesFromText(text) {
  const found = new Set()
  const source = String(text)

  for (const match of source.matchAll(IPV4_IN_TEXT)) {
    const ip = match[1]
    if (ip && isValidIpv4(ip) && !isIgnoredAddress(ip)) found.add(ip)
  }

  for (const match of source.matchAll(IPV6_IN_TEXT)) {
    const ip = match[1]
    if (ip && isValidIpv6(ip) && !isIgnoredAddress(ip)) {
      found.add(ip.toLowerCase())
    }
  }

  // Also scan whitespace-delimited tokens (handles compressed IPv6 reliably)
  for (const token of source.split(/[\s,;|]+/)) {
    const cleaned = token.replace(/^\[/, '').replace(/\]:?$/, '')
    if (!cleaned || isIgnoredAddress(cleaned)) continue
    if (isValidIpv4(cleaned) || isValidIpv6(cleaned) || isMdnsHostname(cleaned)) {
      found.add(cleaned.includes(':') || cleaned.endsWith('.local') ? cleaned.toLowerCase() : cleaned)
    }
  }

  for (const match of source.matchAll(MDNS_IN_TEXT)) {
    if (match[1]) found.add(match[1].toLowerCase())
  }

  return [...found]
}

/**
 * @param {ParsedIceCandidate[]} candidates
 * @returns {Record<IceCandidateType, ParsedIceCandidate[]>}
 */
export function groupByCandidateType(candidates) {
  /** @type {Record<IceCandidateType, ParsedIceCandidate[]>} */
  const groups = { host: [], srflx: [], prflx: [], relay: [], unknown: [] }
  for (const c of candidates) {
    groups[c.type].push(c)
  }
  return groups
}
