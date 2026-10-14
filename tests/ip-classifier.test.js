import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import {
  classifyAddress,
  groupAddresses,
  isMdnsHostname,
  isPrivateIp,
  isValidIpv4,
  isValidIpv6
} from '../src/ip-classifier.js'

describe('ip-classifier', () => {
  it('validates IPv4', () => {
    assert.equal(isValidIpv4('192.168.1.1'), true)
    assert.equal(isValidIpv4('256.0.0.1'), false)
  })

  it('validates IPv6', () => {
    assert.equal(isValidIpv6('2001:db8::1'), true)
    assert.equal(isValidIpv6('::1'), true)
    assert.equal(isValidIpv6('::ffff:192.0.2.1'), true)
    assert.equal(isValidIpv6('not-an-ip'), false)
  })

  it('detects private IPv4 ranges', () => {
    assert.equal(isPrivateIp('10.0.0.5'), true)
    assert.equal(isPrivateIp('172.16.0.1'), true)
    assert.equal(isPrivateIp('192.168.0.1'), true)
    assert.equal(isPrivateIp('169.254.1.1'), true)
    assert.equal(isPrivateIp('100.64.0.1'), true)
    assert.equal(isPrivateIp('8.8.8.8'), false)
  })

  it('detects private IPv6 ranges', () => {
    assert.equal(isPrivateIp('fe80::1'), true)
    assert.equal(isPrivateIp('fd12:3456::1'), true)
    assert.equal(isPrivateIp('2001:db8::1'), false)
  })

  it('detects mDNS hostnames', () => {
    assert.equal(isMdnsHostname('abc.local'), true)
    assert.equal(
      isMdnsHostname('a1b2c3d4-e5f6-7890-abcd-ef1234567890.local'),
      true
    )
    assert.equal(isMdnsHostname('example.com'), false)
  })

  it('classifies address kinds', () => {
    assert.equal(classifyAddress('127.0.0.1'), 'ignored')
    assert.equal(classifyAddress('192.168.1.20'), 'private')
    assert.equal(classifyAddress('203.0.113.9'), 'public')
    assert.equal(classifyAddress('foo.local'), 'mdns')
  })

  it('groups addresses without treating private/mdns as public', () => {
    const grouped = groupAddresses([
      '192.168.1.1',
      '203.0.113.5',
      'host.local',
      '127.0.0.1',
      '203.0.113.5'
    ])
    assert.deepEqual(grouped.private, ['192.168.1.1'])
    assert.deepEqual(grouped.public, ['203.0.113.5'])
    assert.deepEqual(grouped.mdns, ['host.local'])
  })
})
