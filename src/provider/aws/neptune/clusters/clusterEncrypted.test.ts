import 'mocha'
import { useFakeTimers, SinonFakeTimers } from 'sinon'
import { mock, restore } from 'aws-sdk-mock'
import { handler } from './clusterEncrypted'
import { expect } from 'chai'

describe('neptune cluster storage is encrypted at rest', () => {
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
    mock('Neptune', 'describeDBClusters', {
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

    mock('Neptune', 'describeDBClusters', {})

    audits = await handler({
      region: 'all',
      profile: 'test',
      keyType: 'cmk',
    })
    expect(audits).to.eql([])
  })

  it('should report FAIL if the cluster is not encrypted', async () => {
    mock('Neptune', 'describeDBClusters', {
      DBClusters: [
        {
          DBClusterIdentifier: 'test',
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
        rule: 'ClusterEncrypted',
        service: 'neptune',
        state: 'FAIL',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })

  it('should report OK if the cluster is encrypted with key type aws', async () => {
    mock('KMS', 'describeKey', {
      KeyMetadata: { Arn: 'test', KeyManager: 'AWS' },
    })
    mock('Neptune', 'describeDBClusters', {
      DBClusters: [
        {
          DBClusterIdentifier: 'test',
          KmsKeyId: 'test',
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
        rule: 'ClusterEncrypted',
        service: 'neptune',
        state: 'OK',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })

  it('should report WARNING when cluster is encrypted with an aws managed key', async () => {
    mock('KMS', 'describeKey', {
      KeyMetadata: { Arn: 'test', KeyManager: 'AWS' },
    })
    mock('Neptune', 'describeDBClusters', {
      DBClusters: [
        {
          DBClusterIdentifier: 'test',
          KmsKeyId: 'test',
        },
      ],
    })

    const audits = await handler({
      resourceId: 'test',
      region: 'test',
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
        service: 'neptune',
        state: 'WARNING',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })

  it('should report OK when cluster is encrypted with a cmk', async () => {
    mock('KMS', 'describeKey', {
      KeyMetadata: { Arn: 'test', KeyManager: 'CUSTOMER' },
    })
    mock('Neptune', 'describeDBClusters', {
      DBClusters: [
        {
          DBClusterIdentifier: 'test',
          KmsKeyId: 'test',
        },
      ],
    })

    const audits = await handler({
      resourceId: 'test',
      region: 'test',
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
        service: 'neptune',
        state: 'OK',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })
})
