import 'mocha'
import { expect } from 'chai'
import { useFakeTimers, SinonFakeTimers } from 'sinon'
import { mock, restore } from 'aws-sdk-mock'
import { handler, QueueEncryptedCliInterface } from './queueEncrypted'

describe('sqs topic encryption', () => {
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

  it('should report nothing if no queues are found', async () => {
    mock('SQS', 'listQueues', {
      QueueUrls: [],
    })

    const audits = await handler({
      region: 'us-east-1',
      profile: 'test',
      domain: 'pub',
      keyType: 'aws',
    } as QueueEncryptedCliInterface)
    expect(audits).to.eql([])
  })

  it('should report FAIL for queues that are not encrypted', async () => {
    mock('SQS', 'listQueues', {
      QueueUrls: ['test'],
    })
    mock('SQS', 'getQueueAttributes', {})
    const audits = await handler({
      region: 'us-east-1',
      profile: 'test',
      domain: 'pub',
      keyType: 'aws',
    } as QueueEncryptedCliInterface)
    expect(audits).to.eql([
      {
        name: 'test',
        physicalId: 'test',
        profile: 'test',
        provider: 'aws',
        region: 'us-east-1',
        rule: 'QueueEncrypted',
        service: 'sqs',
        state: 'FAIL',
        time: now.toISOString(),
      },
    ])
  })

  it('should report FAIL when a queue is not encrypted', async () => {
    mock('SQS', 'listQueues', {
      QueueUrls: ['test'],
    })
    mock('SQS', 'getQueueAttributes', {})
    const audits = await handler({
      region: 'us-east-1',
      profile: 'test',
      domain: 'pub',
      keyType: 'aws',
    } as QueueEncryptedCliInterface)
    expect(audits).to.eql([
      {
        name: 'test',
        physicalId: 'test',
        profile: 'test',
        provider: 'aws',
        region: 'us-east-1',
        rule: 'QueueEncrypted',
        service: 'sqs',
        state: 'FAIL',
        time: now.toISOString(),
      },
    ])
  })

  it('should report OK when a queue is encrypted', async () => {
    mock('SQS', 'listQueues', {
      QueueUrls: ['test'],
    })
    mock('SQS', 'getQueueAttributes', {
      Attributes: {
        KmsMasterKeyId: 'test',
      },
    })
    mock('KMS', 'describeKey', {
      KeyMetadata: { Arn: 'test', KeyManager: 'AWS' },
    })
    const audits = await handler({
      region: 'us-east-1',
      profile: 'test',
      domain: 'pub',
      keyType: 'aws',
    } as QueueEncryptedCliInterface)
    expect(audits).to.eql([
      {
        name: 'test',
        physicalId: 'test',
        profile: 'test',
        provider: 'aws',
        region: 'us-east-1',
        rule: 'QueueEncrypted',
        service: 'sqs',
        state: 'OK',
        time: now.toISOString(),
      },
    ])
  })

  it('should report FAIL when attributes are returned w/o an encryption key id', async () => {
    mock('SQS', 'listQueues', {
      QueueUrls: ['test'],
    })
    mock('SQS', 'getQueueAttributes', {
      Attributes: {},
    })
    const audits = await handler({
      region: 'us-east-1',
      profile: 'test',
      domain: 'pub',
      keyType: 'aws',
    } as QueueEncryptedCliInterface)
    expect(audits).to.eql([
      {
        name: 'test',
        physicalId: 'test',
        profile: 'test',
        provider: 'aws',
        region: 'us-east-1',
        rule: 'QueueEncrypted',
        service: 'sqs',
        state: 'FAIL',
        time: now.toISOString(),
      },
    ])
  })

  it('should report OK when scanning a single resource that is encrypted', async () => {
    mock('SQS', 'listQueues', {
      QueueUrls: ['test'],
    })
    mock('SQS', 'getQueueAttributes', {
      Attributes: {
        KmsMasterKeyId: 'test',
      },
    })
    mock('KMS', 'describeKey', {
      KeyMetadata: { Arn: 'test', KeyManager: 'AWS' },
    })
    const audits = await handler({
      region: 'us-east-1',
      profile: 'test',
      domain: 'pub',
      keyType: 'aws',
      resourceId: 'test',
    } as QueueEncryptedCliInterface)
    expect(audits).to.eql([
      {
        name: 'test',
        physicalId: 'test',
        profile: 'test',
        provider: 'aws',
        region: 'us-east-1',
        rule: 'QueueEncrypted',
        service: 'sqs',
        state: 'OK',
        time: now.toISOString(),
      },
    ])
  })
})
