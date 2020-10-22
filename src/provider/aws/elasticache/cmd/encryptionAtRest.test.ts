import 'mocha'
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

  // it('should report OK when looking for aws key types', async () => {
  //   mock('RDS', 'describeDBClusters', {
  //     DBClusters: [
  //       {
  //         DBClusterArn: 'test',
  //         KmsKeyId: 'test',
  //         StorageEncrypted: true,
  //       },
  //     ],
  //   })

  //   mock('KMS', 'describeKey', {
  //     KeyMetadata: { Arn: 'test', KeyManager: 'AWS' },
  //   })

  //   const audits = await handler({
  //     region: 'test',
  //     profile: 'test',
  //     keyType: 'aws',
  //   })
  //   expect(audits).to.eql([
  //     {
  //       physicalId: 'test',
  //       profile: 'test',
  //       provider: 'aws',
  //       region: 'test',
  //       rule: 'ClusterEncrypted',
  //       service: 'rds',
  //       state: 'OK',
  //       time: '1970-01-01T00:00:00.000Z',
  //     },
  //   ])
  // })
})
