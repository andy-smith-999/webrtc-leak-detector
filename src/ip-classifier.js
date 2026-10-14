/**
 * IP / hostname classification for WebRTC ICE addresses.
 * Private or mDNS addresses are NOT treated as public IP leaks.
 */

const IGNORED = new Set(['0.0.0.0', '127.0.0.1', '::', '::1'])

const IPV4_RE =
  /^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$/

/**
 * @param {string} value
 * @returns {boolean}
 */
export function isIgnoredAddress(value) {
  return IGNORED.has(String(value).toLowerCase())
}

/**
 * @param {string} value
 * @returns {boolean}
 */
export function isMdnsHostname(value) {
  const v = String(value).toLowerCase()
  return v.endsWith('.local') || /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.local$/.test(v)
}

/**
 * @param {string} ip
 * @returns {boolean}
 */
export function isValidIpv4(ip) {
  return IPV4_RE.test(ip)
}

/**
 * Lightweight IPv6 check (covers common ICE forms).
 * @param {string} value
 * @returns {boolean}
 */
export function isValidIpv6(value) {
  const [addr, zone] = String(value).split('%')
  if (!addr || !/^[0-9a-fA-F:.]+$/.test(addr)) return false
  if (zone !== undefined && !/^[\w.-]+$/.test(zone)) return false

  if (addr.includes('.')) {
    const lastColon = addr.lastIndexOf(':')
    if (lastColon === -1) return false
    const v4Part = addr.slice(lastColon + 1)
    const v6Prefix = addr.slice(0, lastColon)
    return isValidIpv4(v4Part) && /^[0-9a-fA-F:]*$/i.test(v6Prefix)
  }

  if ((addr.match(/::/g) || []).length > 1) return false

  let groupCount = 0
  for (const segment of addr.split(':')) {
    if (segment === '') continue
    if (!/^[0-9a-fA-F]{1,4}$/.test(segment)) return false
    groupCount++
  }

  if (addr.includes('::')) return groupCount <= 7
  return groupCount === 8
}

/**
 * @param {string} ip
 * @returns {boolean}
 */
function isPrivateIpv4(ip) {
  const parts = ip.split('.').map(Number)
  if (parts.length !== 4 || parts.some((p) => Number.isNaN(p) || p < 0 || p > 255)) {
    return false
  }
  if (parts[0] === 10) return true
  if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true
  if (parts[0] === 192 && parts[1] === 168) return true
  if (parts[0] === 127) return true
  if (parts[0] === 169 && parts[1] === 254) return true
  if (parts[0] === 100 && parts[1] >= 64 && parts[1] <= 127) return true // CGNAT
  return false
}

/**
 * @param {string} ip
 * @returns {boolean}
 */
function isPrivateIpv6(ip) {
  const lower = ip.toLowerCase()
  if (lower === '::1') return true
  if (lower.startsWith('fe80:')) return true
  if (lower.startsWith('fc') || lower.startsWith('fd')) return true
  if (lower.startsWith('::ffff:')) {
    const mapped = lower.slice('::ffff:'.length)
    if (isValidIpv4(mapped)) return isPrivateIpv4(mapped)
  }
  return false
}

/**
 * @param {string} address
 * @returns {boolean}
 */
export function isPrivateIp(address) {
  const ip = String(address).toLowerCase()
  if (ip.includes('.')) return isPrivateIpv4(ip)
  if (ip.includes(':')) return isPrivateIpv6(ip)
  return false
}

/**
 * @typedef {'ignored' | 'mdns' | 'private' | 'public' | 'hostname' | 'unknown'} AddressKind
 */

/**
 * @param {string} address
 * @returns {AddressKind}
 */
export function classifyAddress(address) {
  const value = String(address).trim()
  if (!value) return 'unknown'
  if (isIgnoredAddress(value)) return 'ignored'
  if (isMdnsHostname(value)) return 'mdns'
  if (isValidIpv4(value) || isValidIpv6(value)) {
    return isPrivateIp(value) ? 'private' : 'public'
  }
  // Non-IP hostnames that are not clearly mDNS
  if (/[a-zA-Z]/.test(value)) return 'hostname'
  return 'unknown'
}

/**
 * @param {string[]} addresses
 * @returns {{ private: string[], public: string[], mdns: string[], other: string[] }}
 */
export function groupAddresses(addresses) {
  const privateIps = []
  const publicIps = []
  const mdns = []
  const other = []

  for (const addr of [...new Set(addresses)]) {
    const kind = classifyAddress(addr)
    if (kind === 'ignored') continue
    if (kind === 'private') privateIps.push(addr)
    else if (kind === 'public') publicIps.push(addr)
    else if (kind === 'mdns') mdns.push(addr)
    else other.push(addr)
  }

  return { private: privateIps, public: publicIps, mdns, other }
}
