import { useFakeTimers, SinonFakeTimers } from 'sinon'
import { mock, restore } from 'aws-sdk-mock'
import { handler } from './encryptionAtRest'
import { expect } from 'chai'

describe('elasticache cluster storage is encrypted at rest', () => {
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
    mock('ElastiCache', 'describeCacheClusters', {
      CacheClusters: [],
    })

    const audits = await handler({
      region: 'test',
      profile: 'test',
      keyType: 'aws',
    })
    expect(audits).to.eql([])
  })

  it('should report nothing if no clusters are reported', async () => {
    mock('ElastiCache', 'describeCacheClusters', {})

    const audits = await handler({
      region: 'test',
      profile: 'test',
      keyType: 'aws',
    })
    expect(audits).to.eql([])
  })

  it('should report FAIL if the cluster is not encrypted at rest', async () => {
    mock('ElastiCache', 'describeCacheClusters', {
      CacheClusters: [
        {
          CacheClusterId: 'test',
          AtRestEncryptionEnabled: false,
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
        rule: 'EncryptionAtRest',
        service: 'elasticache',
        state: 'FAIL',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })

  it('should report OK if the cluster is encrypted at rest', async () => {
    mock('ElastiCache', 'describeCacheClusters', {
      CacheClusters: [
        {
          CacheClusterId: 'test',
          Engine: 'redis',
          AtRestEncryptionEnabled: true,
          ReplicationGroupId: 'test',
        },
      ],
    })

    mock('ElastiCache', 'describeReplicationGroups', {
      ReplicationGroups: [
        {
          KmsKeyId: 'test',
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
        rule: 'EncryptionAtRest',
        service: 'elasticache',
        state: 'OK',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })

  it('should report UNKNOWN there are no replication groups found', async () => {
    mock('ElastiCache', 'describeCacheClusters', {
      CacheClusters: [
        {
          CacheClusterId: 'test',
          Engine: 'redis',
          AtRestEncryptionEnabled: true,
          ReplicationGroupId: 'test',
        },
      ],
    })

    mock('ElastiCache', 'describeReplicationGroups', {})

    mock('KMS', 'describeKey', {
      KeyMetadata: { Arn: 'test', KeyManager: 'AWS' },
    })

    const audits = await handler({
      region: 'test',
      profile: 'test',
      resourceId: 'test',
      keyType: 'aws',
    })
    expect(audits).to.eql([
      {
        physicalId: 'test',
        profile: 'test',
        provider: 'aws',
        region: 'test',
        rule: 'EncryptionAtRest',
        service: 'elasticache',
        state: 'UNKNOWN',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })

  it('should report UNKNOWN if a non redis cluster is encrypted at rest', async () => {
    mock('ElastiCache', 'describeCacheClusters', {
      CacheClusters: [
        {
          CacheClusterId: 'test',
          Engine: 'test',
          AtRestEncryptionEnabled: true,
          ReplicationGroupId: 'test',
        },
      ],
    })

    const audits = await handler({
      region: 'test',
      profile: 'test',
      resourceId: 'test',
      keyType: 'aws',
    })
    expect(audits).to.eql([
      {
        physicalId: 'test',
        profile: 'test',
        provider: 'aws',
        region: 'test',
        rule: 'EncryptionAtRest',
        service: 'elasticache',
        state: 'UNKNOWN',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })

  it('should report FAIL for encrypted redis clusters that do not show a kms key id', async () => {
    mock('ElastiCache', 'describeCacheClusters', {
      CacheClusters: [
        {
          CacheClusterId: 'test',
          Engine: 'redis',
          AtRestEncryptionEnabled: true,
          ReplicationGroupId: 'test',
        },
      ],
    })

    mock('ElastiCache', 'describeReplicationGroups', {
      ReplicationGroups: [
        {
          test: 'test',
        },
      ],
    })

    mock('KMS', 'describeKey', {
      KeyMetadata: { Arn: 'test', KeyManager: 'AWS' },
    })

    const audits = await handler({
      region: 'test',
      profile: 'test',
      resourceId: 'test',
      keyType: 'aws',
    })
    expect(audits).to.eql([
      {
        physicalId: 'test',
        profile: 'test',
        provider: 'aws',
        region: 'test',
        rule: 'EncryptionAtRest',
        service: 'elasticache',
        state: 'FAIL',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })

  it('should report WARNING for encrypted clusters with the wrong key type', async () => {
    mock('ElastiCache', 'describeCacheClusters', {
      CacheClusters: [
        {
          CacheClusterId: 'test',
          Engine: 'redis',
          AtRestEncryptionEnabled: true,
          ReplicationGroupId: 'test',
        },
      ],
    })

    mock('ElastiCache', 'describeReplicationGroups', {
      ReplicationGroups: [
        {
          KmsKeyId: 'test',
        },
      ],
    })

    mock('KMS', 'describeKey', {
      KeyMetadata: { Arn: 'test', KeyManager: 'AWS' },
    })

    const audits = await handler({
      region: 'test',
      profile: 'test',
      resourceId: 'test',
      keyType: 'cmk',
    })
    expect(audits).to.eql([
      {
        physicalId: 'test',
        profile: 'test',
        provider: 'aws',
        region: 'test',
        rule: 'EncryptionAtRest',
        service: 'elasticache',
        state: 'WARNING',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })

  it('should report OK for encrypted clusters with the correct key type', async () => {
    mock('ElastiCache', 'describeCacheClusters', {
      CacheClusters: [
        {
          CacheClusterId: 'test',
          Engine: 'redis',
          AtRestEncryptionEnabled: true,
          ReplicationGroupId: 'test',
        },
      ],
    })

    mock('ElastiCache', 'describeReplicationGroups', {
      ReplicationGroups: [
        {
          KmsKeyId: 'test',
        },
      ],
    })

    mock('KMS', 'describeKey', {
      KeyMetadata: { Arn: 'test', KeyManager: 'CUSTOMER' },
    })

    const audits = await handler({
      region: 'test',
      profile: 'test',
      resourceId: 'test',
      keyType: 'cmk',
    })
    expect(audits).to.eql([
      {
        physicalId: 'test',
        profile: 'test',
        provider: 'aws',
        region: 'test',
        rule: 'EncryptionAtRest',
        service: 'elasticache',
        state: 'OK',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })
})
