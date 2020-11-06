import 'mocha'
import { useFakeTimers, SinonFakeTimers } from 'sinon'
import { mock, restore } from 'aws-sdk-mock'
import { handler } from './encryptionAtRest'
import { expect } from 'chai'

describe('dynamodb table encrypted at rest', () => {
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

  it('should report nothing if no tables are found', async () => {
    mock('DynamoDB', 'listTables', {
      TableNames: [],
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

    mock('DynamoDB', 'listTables', {})

    audits = await handler({
      region: 'all',
      profile: 'test',
      keyType: 'cmk',
    })
    expect(audits).to.eql([])
  })

  // it('should report WARNING if the table is encrypted with default settings', async () => {
  //   mock('DynamoDB', 'describeTable', {
  //     Table: {
  //       TableName: 'test',
  //       SSEDescription: undefined,
  //     },
  //   })

  //   const audits = await handler({
  //     region: 'test',
  //     profile: 'test',
  //     keyType: 'aws',
  //   })
  //   console.log('this is audits ...', audits)
  //   expect(audits).to.eql([
  //     {
  //       physicalId: 'test',
  //       profile: 'test',
  //       provider: 'aws',
  //       region: 'test',
  //       rule: 'EncryptionAtRest',
  //       service: 'dynamodb',
  //       state: 'WARNING',
  //       time: '1970-01-01T00:00:00.000Z',
  //     },
  //   ])
  // })

  // it('should report OK if the table is encrypted with key type aws', async () => {
  //   mock('KMS', 'describeKey', {
  //     KeyMetadata: { Arn: 'test', KeyManager: 'AWS' },
  //   })
  //   mock('DynamoDB', 'describeTable', {
  //     Table: {
  //       TableName: 'test',
  //       SSEDescription: {
  //         KMSMasterKeyArn: 'test',
  //       },
  //     },
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
  //       rule: 'EncryptionAtRest',
  //       service: 'dynamodb',
  //       state: 'OK',
  //       time: '1970-01-01T00:00:00.000Z',
  //     },
  //   ])
  // })

  // it('should report WARNING when cluster is encrypted with an aws managed key', async () => {
  //   mock('KMS', 'describeKey', {
  //     KeyMetadata: { Arn: 'test', KeyManager: 'AWS' },
  //   })
  //   mock('Neptune', 'describeDBClusters', {
  //     DBClusters: [
  //       {
  //         DBClusterIdentifier: 'test',
  //         KmsKeyId: 'test',
  //       },
  //     ],
  //   })

  //   const audits = await handler({
  //     resourceId: 'test',
  //     region: 'test',
  //     profile: 'test',
  //     keyType: 'cmk',
  //   })
  //   expect(audits).to.eql([
  //     {
  //       physicalId: 'test',
  //       profile: 'test',
  //       provider: 'aws',
  //       region: 'test',
  //       rule: 'ClusterEncrypted',
  //       service: 'neptune',
  //       state: 'WARNING',
  //       time: '1970-01-01T00:00:00.000Z',
  //     },
  //   ])
  // })

  // it('should report OK when cluster is encrypted with a cmk', async () => {
  //   mock('KMS', 'describeKey', {
  //     KeyMetadata: { Arn: 'test', KeyManager: 'CUSTOMER' },
  //   })
  //   mock('Neptune', 'describeDBClusters', {
  //     DBClusters: [
  //       {
  //         DBClusterIdentifier: 'test',
  //         KmsKeyId: 'test',
  //       },
  //     ],
  //   })

  //   const audits = await handler({
  //     resourceId: 'test',
  //     region: 'test',
  //     profile: 'test',
  //     keyType: 'cmk',
  //   })
  //   expect(audits).to.eql([
  //     {
  //       physicalId: 'test',
  //       profile: 'test',
  //       provider: 'aws',
  //       region: 'test',
  //       rule: 'ClusterEncrypted',
  //       service: 'neptune',
  //       state: 'OK',
  //       time: '1970-01-01T00:00:00.000Z',
  //     },
  //   ])
  // })
})
