import 'mocha'
import { useFakeTimers, SinonFakeTimers } from 'sinon'
import { restore, mock } from 'aws-sdk-mock'
import { handler } from './keyRotationEnabled'
import { expect } from 'chai'

describe('cmk rotation enabled', () => {
  const now = new Date(0)
  let clock: SinonFakeTimers

  beforeEach(() => {
    clock = useFakeTimers(now)
    mock('EC2', 'describeRegions', { Regions: [{ RegionName: 'us-east-1' }] })
  })

  afterEach(() => {
    clock.restore()
    restore()
  })

  it('should report nothing if no "Keys" are returned', async () => {
    mock('KMS', 'listKeys', {})

    const audits = await handler({
      region: 'all',
      profile: 'test',
    })
    expect(audits).to.eql([])
  })

  it('should report nothing if no keys in the key array are found', async () => {
    mock('KMS', 'listKeys', { Keys: [] })

    const audits = await handler({
      region: 'all',
      profile: 'test',
    })
    expect(audits).to.eql([])
  })

  it('should report nothing if the key manager is AWS', async () => {
    mock('KMS', 'listKeys', { Keys: [{ KeyArn: 'test' }] })
    mock('KMS', 'describeKey', {
      KeyMetadata: {
        KeyManager: 'AWS',
      },
    })
    mock('KMS', 'getKeyRotationStatus', { KeyRotationEnabled: true })

    const audits = await handler({
      region: 'all',
      profile: 'test',
    })
    expect(audits).to.eql([])
  })

  it('should report OK if key rotation is enabled', async () => {
    mock('KMS', 'listKeys', { Keys: [{ KeyArn: 'test' }] })
    mock('KMS', 'describeKey', {
      KeyMetadata: {
        KeyManager: 'CUSTOMER',
      },
    })
    mock('KMS', 'getKeyRotationStatus', { KeyRotationEnabled: true })

    const audits = await handler({
      region: 'all',
      profile: 'test',
    })
    expect(audits).to.eql([
      {
        physicalId: 'test',
        profile: 'test',
        provider: 'aws',
        region: 'us-east-1',
        rule: 'KeyRotationEnabled',
        service: 'kms',
        state: 'OK',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })

  it('should report FAIL if key rotation is not enabled', async () => {
    mock('KMS', 'listKeys', { Keys: [{ KeyArn: 'test' }] })
    mock('KMS', 'describeKey', {
      KeyMetadata: {
        KeyManager: 'CUSTOMER',
      },
    })
    mock('KMS', 'getKeyRotationStatus', { KeyRotationEnabled: false })

    const audits = await handler({
      region: 'all',
      profile: 'test',
    })
    expect(audits).to.eql([
      {
        physicalId: 'test',
        profile: 'test',
        provider: 'aws',
        region: 'us-east-1',
        rule: 'KeyRotationEnabled',
        service: 'kms',
        state: 'FAIL',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })

  it('should report OK if key rotation is enabled for a single resource', async () => {
    mock('KMS', 'listKeys', { Keys: [{ KeyArn: 'test' }] })
    mock('KMS', 'describeKey', {
      KeyMetadata: {
        KeyManager: 'CUSTOMER',
      },
    })
    mock('KMS', 'getKeyRotationStatus', { KeyRotationEnabled: true })

    const audits = await handler({
      region: 'test',
      resourceId: 'test',
      profile: 'test',
    })
    expect(audits).to.eql([
      {
        physicalId: 'test',
        profile: 'test',
        provider: 'aws',
        region: 'test',
        rule: 'KeyRotationEnabled',
        service: 'kms',
        state: 'OK',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })

  it('should report UNKNOWN if key rotation is undefined', async () => {
    mock('KMS', 'listKeys', { Keys: [{ KeyArn: 'test' }] })
    mock('KMS', 'describeKey', {
      KeyMetadata: {
        KeyManager: 'CUSTOMER',
      },
    })
    mock('KMS', 'getKeyRotationStatus', {})

    const audits = await handler({
      region: 'all',
      profile: 'test',
    })
    expect(audits).to.eql([
      {
        physicalId: 'test',
        profile: 'test',
        provider: 'aws',
        region: 'us-east-1',
        rule: 'KeyRotationEnabled',
        service: 'kms',
        state: 'UNKNOWN',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })
})
