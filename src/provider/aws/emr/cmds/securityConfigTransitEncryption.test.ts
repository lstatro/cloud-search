import { SinonFakeTimers, useFakeTimers } from 'sinon'
import { mock, restore } from 'aws-sdk-mock'

import { expect } from 'chai'
import { handler } from './securityConfigTransitEncryption'

describe('emr cluster security configurations should have transit encryption', () => {
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

  it('should report nothing if list returns without a security config attribute', async () => {
    mock('EMR', 'listSecurityConfigurations', {})

    const audits = await handler({ region: 'all' })

    expect(audits).to.eql([])
  })

  it('should report nothing if list returns an empty a array', async () => {
    mock('EMR', 'listSecurityConfigurations', { SecurityConfigurations: [] })

    const audits = await handler({ region: 'all' })

    expect(audits).to.eql([])
  })

  it('should report OK if the security config has transit encryption set', async () => {
    mock('EMR', 'listSecurityConfigurations', {
      SecurityConfigurations: [{ Name: 'test' }],
    })

    mock('EMR', 'describeSecurityConfiguration', {
      SecurityConfiguration: JSON.stringify({
        EncryptionConfiguration: {
          EnableInTransitEncryption: true,
        },
      }),
    })

    const audits = await handler({ region: 'all' })

    expect(audits).to.eql([
      {
        physicalId: 'test',
        profile: undefined,
        provider: 'aws',
        region: 'us-east-1',
        rule: 'TransitEncryption',
        service: 'emr',
        state: 'OK',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })

  it('should report FAIL if the security config does not have a SecurityConfiguration attribute', async () => {
    mock('EMR', 'listSecurityConfigurations', {
      SecurityConfigurations: [{ Name: 'test' }],
    })

    mock('EMR', 'describeSecurityConfiguration', {})

    const audits = await handler({ region: 'all' })

    expect(audits).to.eql([
      {
        physicalId: 'test',
        profile: undefined,
        provider: 'aws',
        region: 'us-east-1',
        rule: 'TransitEncryption',
        service: 'emr',
        state: 'FAIL',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })

  it('should report FAIL if the security config does not have a EncryptionConfiguration attribute', async () => {
    mock('EMR', 'listSecurityConfigurations', {
      SecurityConfigurations: [{ Name: 'test' }],
    })

    mock('EMR', 'describeSecurityConfiguration', {
      SecurityConfiguration: JSON.stringify({}),
    })

    const audits = await handler({ region: 'all' })

    expect(audits).to.eql([
      {
        physicalId: 'test',
        profile: undefined,
        provider: 'aws',
        region: 'us-east-1',
        rule: 'TransitEncryption',
        service: 'emr',
        state: 'FAIL',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })

  it('should report FAIL if the security config does not have a EnableInTransitEncryption attribute', async () => {
    mock('EMR', 'listSecurityConfigurations', {
      SecurityConfigurations: [{ Name: 'test' }],
    })

    mock('EMR', 'describeSecurityConfiguration', {
      SecurityConfiguration: JSON.stringify({ EncryptionConfiguration: {} }),
    })

    const audits = await handler({ region: 'all' })

    expect(audits).to.eql([
      {
        physicalId: 'test',
        profile: undefined,
        provider: 'aws',
        region: 'us-east-1',
        rule: 'TransitEncryption',
        service: 'emr',
        state: 'FAIL',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })

  it('should report FAIL if the security config EnableInTransitEncryption attribute is false', async () => {
    mock('EMR', 'listSecurityConfigurations', {
      SecurityConfigurations: [{ Name: 'test' }],
    })

    mock('EMR', 'describeSecurityConfiguration', {
      SecurityConfiguration: JSON.stringify({
        EncryptionConfiguration: { EnableInTransitEncryption: false },
      }),
    })

    const audits = await handler({ region: 'all' })

    expect(audits).to.eql([
      {
        physicalId: 'test',
        profile: undefined,
        provider: 'aws',
        region: 'us-east-1',
        rule: 'TransitEncryption',
        service: 'emr',
        state: 'FAIL',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })

  it('should report WARNING if the security config does not JSON parse', async () => {
    mock('EMR', 'listSecurityConfigurations', {
      SecurityConfigurations: [{ Name: 'test' }],
    })

    mock('EMR', 'describeSecurityConfiguration', {
      SecurityConfiguration: 'test',
    })

    const audits = await handler({ region: 'us-east-1', resource: 'test' })

    expect(audits).to.eql([
      {
        physicalId: 'test',
        profile: undefined,
        provider: 'aws',
        region: 'us-east-1',
        rule: 'TransitEncryption',
        service: 'emr',
        state: 'WARNING',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })
})
