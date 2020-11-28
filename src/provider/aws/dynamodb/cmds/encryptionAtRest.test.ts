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

  it('should report WARNING if the table is encrypted with default settings', async () => {
    mock('DynamoDB', 'listTables', {
      TableNames: ['test'],
    })
    mock('DynamoDB', 'describeTable', {
      Table: {
        TableName: 'test',
        SSEDescription: undefined,
      },
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
        service: 'dynamodb',
        state: 'WARNING',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })

  it('should report OK if the table is encrypted with key type aws', async () => {
    mock('KMS', 'describeKey', {
      KeyMetadata: { ARN: 'test', KeyManager: 'AWS' },
    })
    mock('DynamoDB', 'listTables', {
      TableNames: ['test'],
    })
    mock('DynamoDB', 'describeTable', {
      Table: {
        TableName: 'test',
        SSEDescription: {
          KMSMasterKeyArn: 'test/test',
        },
      },
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
        service: 'dynamodb',
        state: 'OK',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })

  it('should return an audit given a resourceId', async () => {
    mock('DynamoDB', 'listTables', {
      TableNames: ['test'],
    })
    mock('DynamoDB', 'describeTable', {
      Table: {
        TableName: 'test',
      },
    })
    const audits = await handler({
      region: 'test',
      profile: 'test',
      keyType: 'aws',
      resourceId: 'test',
    })
    expect(audits).to.eql([
      {
        physicalId: 'test',
        profile: 'test',
        provider: 'aws',
        region: 'test',
        rule: 'EncryptionAtRest',
        service: 'dynamodb',
        state: 'WARNING',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })
  it('should report OK when encrypted with a cmk', async () => {
    mock('KMS', 'describeKey', {
      KeyMetadata: { ARN: 'test', KeyManager: 'CUSTOMER' },
    })
    mock('DynamoDB', 'listTables', {
      TableNames: ['test'],
    })
    mock('DynamoDB', 'describeTable', {
      Table: {
        TableName: 'test',
        SSEDescription: {
          KMSMasterKeyArn: 'test/test',
        },
      },
    })
    const audits = await handler({
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
        rule: 'EncryptionAtRest',
        service: 'dynamodb',
        state: 'OK',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })
  it('should report OK when passed a resourceId and that resource is encrypted with an AWS managed key', async () => {
    mock('KMS', 'describeKey', {
      KeyMetadata: { ARN: 'test', KeyManager: 'AWS' },
    })
    mock('DynamoDB', 'listTables', {
      TableNames: ['test'],
    })
    mock('DynamoDB', 'describeTable', {
      Table: {
        TableName: 'test',
        SSEDescription: {
          KMSMasterKeyArn: 'test/test',
        },
      },
    })
    const audits = await handler({
      region: 'test',
      profile: 'test',
      keyType: 'aws',
      resourceId: 'test',
    })
    expect(audits).to.eql([
      {
        physicalId: 'test',
        profile: 'test',
        provider: 'aws',
        region: 'test',
        rule: 'EncryptionAtRest',
        service: 'dynamodb',
        state: 'OK',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })
  it('should report OK when passed a resourceId and that resource is encrypted with a CUSTOMER managed key', async () => {
    mock('KMS', 'describeKey', {
      KeyMetadata: { ARN: 'test', KeyManager: 'CUSTOMER' },
    })
    mock('DynamoDB', 'listTables', {
      TableNames: ['test'],
    })
    mock('DynamoDB', 'describeTable', {
      Table: {
        TableName: 'test',
        SSEDescription: {
          KMSMasterKeyArn: 'test/test',
        },
      },
    })
    const audits = await handler({
      region: 'test',
      profile: 'test',
      keyType: 'cmk',
      resourceId: 'test',
    })
    expect(audits).to.eql([
      {
        physicalId: 'test',
        profile: 'test',
        provider: 'aws',
        region: 'test',
        rule: 'EncryptionAtRest',
        service: 'dynamodb',
        state: 'OK',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })
  it('should return WARNING when passed a resourceId and that resource is encrypted with DEFAULT', async () => {
    mock('DynamoDB', 'listTables', {
      TableNames: ['test'],
    })
    mock('DynamoDB', 'describeTable', {
      Table: {
        TableName: 'test',
        SSEDescription: undefined,
      },
    })
    const audits = await handler({
      region: 'test',
      profile: 'test',
      keyType: 'aws',
      resourceId: 'test',
    })
    expect(audits).to.eql([
      {
        physicalId: 'test',
        profile: 'test',
        provider: 'aws',
        region: 'test',
        rule: 'EncryptionAtRest',
        service: 'dynamodb',
        state: 'WARNING',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })
  it('should return UNKNOWN when a table is encrypted with a CMK but does not have a KMSKeyARN ', async () => {
    mock('DynamoDB', 'listTables', {
      TableNames: ['test'],
    })
    mock('DynamoDB', 'describeTable', Promise.reject())
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
        service: 'dynamodb',
        state: 'UNKNOWN',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })
})
