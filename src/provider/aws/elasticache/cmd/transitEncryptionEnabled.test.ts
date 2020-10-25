import 'mocha'
import { useFakeTimers, SinonFakeTimers } from 'sinon'
import { mock, restore } from 'aws-sdk-mock'
import { handler } from './transitEncryptionEnabled'
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

  it('should report FAIL if no clusters are reported', async () => {
    mock('ElastiCache', 'describeCacheClusters', {})

    const audits = await handler({
      region: 'test',
      profile: 'test',
      keyType: 'aws',
    })
    expect(audits).to.eql([])
  })

  it('should report FAIL if the cluster does not have transit encryption enabled', async () => {
    mock('ElastiCache', 'describeCacheClusters', {
      CacheClusters: [
        {
          CacheClusterId: 'test',
          TransitEncryptionEnabled: false,
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
        rule: 'TransitEncryptionEnabled',
        service: 'elasticache',
        state: 'FAIL',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })

  it('should report OK if the cluster does has transit encryption enabled', async () => {
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
          TransitEncryptionEnabled: true,
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
        rule: 'TransitEncryptionEnabled',
        service: 'elasticache',
        state: 'OK',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })
})
