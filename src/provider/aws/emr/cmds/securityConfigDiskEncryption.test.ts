import { mock, restore } from 'aws-sdk-mock'
import { useFakeTimers, SinonFakeTimers } from 'sinon'
import { handler } from './securityConfigDiskEncryption'
import { expect } from 'chai'

describe('emr cluster security configurations should have disk encryption', () => {
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

  it('should report OK if the security config has disk encryption set', async () => {
    mock('EMR', 'listSecurityConfigurations', {
      SecurityConfigurations: [{ Name: 'test' }],
    })

    mock('EMR', 'describeSecurityConfiguration', {
      SecurityConfiguration: JSON.stringify({
        EncryptionConfiguration: {
          AtRestEncryptionConfiguration: {
            LocalDiskEncryptionConfiguration: {
              EnableEbsEncryption: true,
            },
          },
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
        rule: 'DiskEncryption',
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
        rule: 'DiskEncryption',
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
        rule: 'DiskEncryption',
        service: 'emr',
        state: 'FAIL',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })

  it('should report FAIL if the security config does not have a AtRestEncryptionConfiguration attribute', async () => {
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
        rule: 'DiskEncryption',
        service: 'emr',
        state: 'FAIL',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })

  it('should report FAIL if the security config does not have a LocalDiskEncryptionConfiguration attribute', async () => {
    mock('EMR', 'listSecurityConfigurations', {
      SecurityConfigurations: [{ Name: 'test' }],
    })

    mock('EMR', 'describeSecurityConfiguration', {
      SecurityConfiguration: JSON.stringify({
        EncryptionConfiguration: {
          AtRestEncryptionConfiguration: {},
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
        rule: 'DiskEncryption',
        service: 'emr',
        state: 'FAIL',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })

  it('should report FAIL if the security config does not have a EnableEbsEncryption attribute', async () => {
    mock('EMR', 'listSecurityConfigurations', {
      SecurityConfigurations: [{ Name: 'test' }],
    })

    mock('EMR', 'describeSecurityConfiguration', {
      SecurityConfiguration: JSON.stringify({
        EncryptionConfiguration: {
          AtRestEncryptionConfiguration: {
            LocalDiskEncryptionConfiguration: {},
          },
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
        rule: 'DiskEncryption',
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

    const audits = await handler({ region: 'us-east-1', resourceId: 'test' })

    expect(audits).to.eql([
      {
        physicalId: 'test',
        profile: undefined,
        provider: 'aws',
        region: 'us-east-1',
        rule: 'DiskEncryption',
        service: 'emr',
        state: 'WARNING',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })
})
