import 'mocha'
import { useFakeTimers, SinonFakeTimers } from 'sinon'
import { mock, restore } from 'aws-sdk-mock'
import { handler } from './clusterEncrypted'
import { expect } from 'chai'

describe('rds cluster storage is encrypted at rest', () => {
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

  it('should report nothing if no clusters are found', async () => {
    mock('RDS', 'describeDBClusters', {
      DBClusters: [],
    })

    let audits

    audits = await handler({
      region: 'test',
      profile: 'test',
      keyType: 'aws',
    })
    expect(audits).to.eql([])

    restore()
    mock('EC2', 'describeRegions', { Regions: [{ RegionName: 'us-east-1' }] })

    mock('RDS', 'describeDBClusters', {})

    audits = await handler({
      region: 'all',
      profile: 'test',
      keyType: 'cmk',
    })
    expect(audits).to.eql([])
  })

  it('should report OK when looking for aws key types', async () => {
    mock('RDS', 'describeDBClusters', {
      DBClusters: [
        {
          DBClusterArn: 'test',
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
        rule: 'ClusterEncrypted',
        service: 'rds',
        state: 'OK',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })

  it('should report FAIL for un-encrypted clusters', async () => {
    mock('RDS', 'describeDBClusters', {
      DBClusters: [
        {
          DBClusterArn: 'test',
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
        rule: 'ClusterEncrypted',
        service: 'rds',
        state: 'FAIL',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })

  it('should report OK for cmk encrypted clusters snapshots', async () => {
    mock('RDS', 'describeDBClusters', {
      DBClusters: [
        {
          DBClusterArn: 'test',
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
        rule: 'ClusterEncrypted',
        service: 'rds',
        state: 'OK',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })

  it('should report WARNING for clusters encrypted with an AWS key when looking for cmk types', async () => {
    mock('RDS', 'describeDBClusters', {
      DBClusters: [
        {
          DBClusterArn: 'test',
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
        rule: 'ClusterEncrypted',
        service: 'rds',
        state: 'WARNING',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })
})
