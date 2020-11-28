import { useFakeTimers, SinonFakeTimers } from 'sinon'
import { mock, restore } from 'aws-sdk-mock'
import { handler } from './instanceEncrypted'
import { expect } from 'chai'

describe('rds public instance', () => {
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

  it('should report nothing if no rds instances are found', async () => {
    mock('RDS', 'describeDBInstances', {
      DBInstances: [],
    })

    let audits

    audits = await handler({
      region: 'all',
      profile: 'test',
      keyType: 'aws',
    })
    expect(audits).to.eql([])

    restore()

    mock('EC2', 'describeRegions', { Regions: [{ RegionName: 'us-east-1' }] })
    mock('RDS', 'describeDBInstances', {})

    audits = await handler({
      region: 'all',
      profile: 'test',
      keyType: 'cmk',
    })
    expect(audits).to.eql([])
  })

  it('should report nothing if no rds instances are reported', async () => {
    mock('RDS', 'describeDBInstances', {})

    const audits = await handler({
      region: 'all',
      profile: 'test',
      keyType: 'aws',
    })
    expect(audits).to.eql([])
  })

  it('should report OK if the instance is encrypted with any key', async () => {
    mock('RDS', 'describeDBInstances', {
      DBInstances: [
        {
          DBInstanceArn: 'test',
          KmsKeyId: 'test',
          StorageEncrypted: true,
        },
      ],
    })

    mock('KMS', 'describeKey', {
      KeyMetadata: { Arn: 'test', KeyManager: 'AWS' },
    })

    const audits = await handler({
      region: 'test',
      profile: 'test',
      keyType: 'aws',
    })
    expect(audits).to.eql([
      {
        physicalId: 'test',
        profile: 'test',
        provider: 'aws',
        region: 'test',
        rule: 'InstanceEncrypted',
        service: 'rds',
        state: 'OK',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })

  it('should report FAIL for un-encrypted clusters', async () => {
    mock('RDS', 'describeDBInstances', {
      DBInstances: [
        {
          DBInstanceArn: 'test',
        },
      ],
    })

    const audits = await handler({
      region: 'test',
      profile: 'test',
      keyType: 'aws',
    })
    expect(audits).to.eql([
      {
        physicalId: 'test',
        profile: 'test',
        provider: 'aws',
        region: 'test',
        rule: 'InstanceEncrypted',
        service: 'rds',
        state: 'FAIL',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })

  it('should report OK when looking for cmk encrypted instances', async () => {
    mock('RDS', 'describeDBInstances', {
      DBInstances: [
        {
          DBInstanceArn: 'test',
          KmsKeyId: 'test',
          StorageEncrypted: true,
        },
      ],
    })

    mock('KMS', 'describeKey', {
      KeyMetadata: { Arn: 'test', KeyManager: 'CUSTOMER' },
    })

    const audits = await handler({
      region: 'test',
      resourceId: 'test',
      profile: 'test',
      keyType: 'cmk',
    })

    expect(audits).to.eql([
      {
        physicalId: 'test',
        profile: 'test',
        provider: 'aws',
        region: 'test',
        rule: 'InstanceEncrypted',
        service: 'rds',
        state: 'OK',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })

  it('should report WARNING for instances encrypted with an AWS key when looking for cmk types', async () => {
    mock('RDS', 'describeDBInstances', {
      DBInstances: [
        {
          DBInstanceArn: 'test',
          KmsKeyId: 'test',
          StorageEncrypted: true,
        },
      ],
    })

    mock('KMS', 'describeKey', {
      KeyMetadata: { Arn: 'test', KeyManager: 'AWS' },
    })

    const audits = await handler({
      region: 'test',
      resourceId: 'test',
      profile: 'test',
      keyType: 'cmk',
    })
    expect(audits).to.eql([
      {
        physicalId: 'test',
        profile: 'test',
        provider: 'aws',
        region: 'test',
        rule: 'InstanceEncrypted',
        service: 'rds',
        state: 'WARNING',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })
})
