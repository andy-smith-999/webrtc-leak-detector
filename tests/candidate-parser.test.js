import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import {
  extractAddressesFromText,
  groupByCandidateType,
  parseIceCandidate
} from '../src/candidate-parser.js'
import { analyzeCandidates } from '../src/detector.js'

describe('candidate-parser', () => {
  it('parses a host candidate', () => {
    const line =
      'candidate:842163049 1 udp 1677729535 192.168.1.10 54321 typ host generation 0'
    const parsed = parseIceCandidate(line)
    assert.ok(parsed)
    assert.equal(parsed.type, 'host')
    assert.equal(parsed.address, '192.168.1.10')
    assert.equal(parsed.port, 54321)
    assert.equal(parsed.protocol, 'udp')
    assert.equal(parsed.addressKind, 'private')
  })

  it('parses a srflx candidate with raddr', () => {
    const line =
      'candidate:1 1 udp 41885439 203.0.113.50 9 typ srflx raddr 0.0.0.0 rport 0'
    const parsed = parseIceCandidate(line)
    assert.ok(parsed)
    assert.equal(parsed.type, 'srflx')
    assert.equal(parsed.address, '203.0.113.50')
    assert.equal(parsed.addressKind, 'public')
    assert.equal(parsed.relatedAddress, '0.0.0.0')
  })

  it('parses mDNS host candidates', () => {
    const line =
      'candidate:1 1 udp 2122260223 a1b2c3d4-e5f6-7890-abcd-ef1234567890.local 52123 typ host'
    const parsed = parseIceCandidate(line)
    assert.ok(parsed)
    assert.equal(parsed.type, 'host')
    assert.equal(parsed.addressKind, 'mdns')
  })

  it('parses relay candidates', () => {
    const line =
      'candidate:2 1 udp 2222086 198.51.100.2 3478 typ relay raddr 203.0.113.1 rport 9'
    const parsed = parseIceCandidate(line)
    assert.ok(parsed)
    assert.equal(parsed.type, 'relay')
  })

  it('extracts mixed addresses from free text', () => {
    const addrs = extractAddressesFromText(
      'foo 10.0.0.1 bar 2001:db8::2 baz uuid.local'
    )
    assert.ok(addrs.includes('10.0.0.1'))
    assert.ok(addrs.includes('2001:db8::2'))
    assert.ok(addrs.includes('uuid.local'))
  })

  it('groups by candidate type', () => {
    const candidates = [
      parseIceCandidate(
        'candidate:1 1 udp 1 192.168.0.2 1 typ host'
      ),
      parseIceCandidate(
        'candidate:2 1 udp 1 203.0.113.2 2 typ srflx'
      )
    ].filter(Boolean)
    const groups = groupByCandidateType(candidates)
    assert.equal(groups.host.length, 1)
    assert.equal(groups.srflx.length, 1)
  })
})

describe('analyzeCandidates verdicts', () => {
  it('does not treat private/mDNS-only as potential_leak', () => {
    const candidates = [
      parseIceCandidate(
        'candidate:1 1 udp 1 192.168.1.5 1000 typ host'
      ),
      parseIceCandidate(
        'candidate:2 1 udp 1 abc.local 1001 typ host'
      )
    ].filter(Boolean)

    const result = analyzeCandidates(candidates, '203.0.113.10')
    assert.equal(result.verdict, 'local_only')
    assert.equal(result.mismatchedPublicIps.length, 0)
  })

  it('flags mismatched public IP as potential_leak', () => {
    const candidates = [
      parseIceCandidate(
        'candidate:1 1 udp 1 198.51.100.20 9 typ srflx'
      )
    ].filter(Boolean)

    const result = analyzeCandidates(candidates, '203.0.113.10')
    assert.equal(result.verdict, 'potential_leak')
    assert.deepEqual(result.mismatchedPublicIps, ['198.51.100.20'])
  })

  it('reports no_public_mismatch when public matches egress', () => {
    const candidates = [
      parseIceCandidate(
        'candidate:1 1 udp 1 203.0.113.10 9 typ srflx'
      ),
      parseIceCandidate(
        'candidate:2 1 udp 1 192.168.0.5 1000 typ host'
      )
    ].filter(Boolean)

    const result = analyzeCandidates(candidates, '203.0.113.10')
    assert.equal(result.verdict, 'no_public_mismatch')
  })
})
