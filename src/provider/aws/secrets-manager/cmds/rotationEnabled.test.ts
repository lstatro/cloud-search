import { SinonFakeTimers, useFakeTimers } from 'sinon'
import { mock, restore } from 'aws-sdk-mock'

import { expect } from 'chai'
import { handler } from './rotationEnabled'

describe('secrets-manager secrets rotation should be enabled', () => {
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

  it('should report nothing is listSecrets returns an empty object', async () => {
    mock('SecretsManager', 'listSecrets', {})

    const audits = await handler({ region: 'test' })

    expect(audits).to.eql([])
  })

  it('should report nothing is listSecrets returns an object with an empty array of secrets', async () => {
    mock('SecretsManager', 'listSecrets', { SecretList: [] })

    const audits = await handler({ region: 'test' })

    expect(audits).to.eql([])
  })

  it('should report FAIL for secrets that explicitly have rotation disabled', async () => {
    mock('SecretsManager', 'listSecrets', {
      SecretList: [{ Name: 'test', RotationEnabled: false }],
    })

    const audits = await handler({ region: 'test' })

    expect(audits).to.eql([
      {
        physicalId: 'test',
        provider: 'aws',
        profile: undefined,
        region: 'test',
        rule: 'RotationEnabled',
        service: 'secrets-manager',
        state: 'FAIL',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })

  it('should report FAIL for secrets that implicitly have rotation disabled', async () => {
    mock('SecretsManager', 'listSecrets', {
      SecretList: [{ Name: 'test' }],
    })

    const audits = await handler({ region: 'test' })

    expect(audits).to.eql([
      {
        physicalId: 'test',
        provider: 'aws',
        profile: undefined,
        region: 'test',
        rule: 'RotationEnabled',
        service: 'secrets-manager',
        state: 'FAIL',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })

  it('should report OK for secrets that implicitly have rotation disabled', async () => {
    mock('SecretsManager', 'listSecrets', {
      SecretList: [{ Name: 'test', RotationEnabled: true }],
    })

    mock('SecretsManager', 'describeSecret', {
      Name: 'test',
      RotationEnabled: true,
    })

    const audits = await handler({
      region: 'test',
      profile: 'test',
      resource: 'test',
    })

    expect(audits).to.eql([
      {
        physicalId: 'test',
        provider: 'aws',
        profile: 'test',
        region: 'test',
        rule: 'RotationEnabled',
        service: 'secrets-manager',
        state: 'OK',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })
})
