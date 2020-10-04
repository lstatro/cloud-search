import 'mocha'
import { useFakeTimers, SinonFakeTimers } from 'sinon'
import { mock, restore } from 'aws-sdk-mock'
import { handler, TopicEncryptedCliInterface } from './topicEncrypted'
import { expect } from 'chai'

describe('sns topic encryption', () => {
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

  it('should report nothing if no topics are found', async () => {
    mock('SNS', 'listTopics', {
      Topics: [],
    })

    const audits = await handler({
      region: 'us-east-1',
      profile: 'test',
      domain: 'pub',
      keyType: 'aws',
    } as TopicEncryptedCliInterface)
    expect(audits).to.eql([])
  })

  it('should report FAIL for topics that are not encrypted', async () => {
    mock('SNS', 'listTopics', {
      Topics: [
        {
          TopicArn: 'test',
        },
      ],
    })
    mock('SNS', 'getTopicAttributes', {
      Attributes: {},
    })
    const audits = await handler({
      region: 'us-east-1',
      profile: 'test',
      domain: 'pub',
      keyType: 'aws',
    } as TopicEncryptedCliInterface)
    expect(audits).to.eql([
      {
        name: 'test',
        physicalId: 'test',
        profile: 'test',
        provider: 'aws',
        region: 'us-east-1',
        rule: 'TopicEncrypted',
        service: 'sns',
        state: 'FAIL',
        time: now.toISOString(),
      },
    ])
  })

  it('should report UNKNOWN for topics without attributes', async () => {
    mock('SNS', 'listTopics', {
      Topics: [
        {
          TopicArn: 'test',
        },
      ],
    })
    mock('SNS', 'getTopicAttributes', { test: { test: 'test' } })
    const audits = await handler({
      region: 'us-east-1',
      profile: 'test',
      domain: 'pub',
      keyType: 'aws',
    } as TopicEncryptedCliInterface)
    expect(audits).to.eql([
      {
        name: 'test',
        physicalId: 'test',
        profile: 'test',
        provider: 'aws',
        region: 'us-east-1',
        rule: 'TopicEncrypted',
        service: 'sns',
        state: 'UNKNOWN',
        time: now.toISOString(),
      },
    ])
  })

  it('should report OK for topics with AWS keys', async () => {
    mock('SNS', 'listTopics', {
      Topics: [
        {
          TopicArn: 'test',
        },
      ],
    })
    mock('SNS', 'getTopicAttributes', {
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
    } as TopicEncryptedCliInterface)
    expect(audits).to.eql([
      {
        name: 'test',
        physicalId: 'test',
        profile: 'test',
        provider: 'aws',
        region: 'us-east-1',
        rule: 'TopicEncrypted',
        service: 'sns',
        state: 'OK',
        time: now.toISOString(),
      },
    ])
  })

  it('should report WARNING for when looking for topics encrypted with CMKs but finds AWS keys', async () => {
    mock('SNS', 'listTopics', {
      Topics: [
        {
          TopicArn: 'test',
        },
      ],
    })
    mock('SNS', 'getTopicAttributes', {
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
      resourceId: 'test',
      keyType: 'cmk',
    } as TopicEncryptedCliInterface)
    expect(audits).to.eql([
      {
        name: 'test',
        physicalId: 'test',
        profile: 'test',
        provider: 'aws',
        region: 'us-east-1',
        rule: 'TopicEncrypted',
        service: 'sns',
        state: 'WARNING',
        time: now.toISOString(),
      },
    ])
  })

  it('should report OK topics encrypted with a CMK when looking for CMKs', async () => {
    mock('SNS', 'listTopics', {
      Topics: [
        {
          TopicArn: 'test',
        },
      ],
    })
    mock('SNS', 'getTopicAttributes', {
      Attributes: {
        KmsMasterKeyId: 'test',
      },
    })
    mock('KMS', 'describeKey', {
      KeyMetadata: { Arn: 'test', KeyManager: 'CUSTOMER' },
    })
    const audits = await handler({
      region: 'us-east-1',
      profile: 'test',
      domain: 'pub',
      resourceId: 'test',
      keyType: 'cmk',
    } as TopicEncryptedCliInterface)
    expect(audits).to.eql([
      {
        name: 'test',
        physicalId: 'test',
        profile: 'test',
        provider: 'aws',
        region: 'us-east-1',
        rule: 'TopicEncrypted',
        service: 'sns',
        state: 'OK',
        time: now.toISOString(),
      },
    ])
  })

  it('should report FAIL topics with poorly form key responses ', async () => {
    mock('SNS', 'listTopics', {
      Topics: [
        {
          TopicArn: 'test',
        },
      ],
    })
    mock('SNS', 'getTopicAttributes', {
      Attributes: {
        KmsMasterKeyId: 'test',
      },
    })
    mock('KMS', 'describeKey', {})
    const audits = await handler({
      region: 'us-east-1',
      profile: 'test',
      domain: 'pub',
      resourceId: 'test',
      keyType: 'cmk',
    } as TopicEncryptedCliInterface)
    expect(audits).to.eql([
      {
        name: 'test',
        physicalId: 'test',
        profile: 'test',
        provider: 'aws',
        region: 'us-east-1',
        rule: 'TopicEncrypted',
        service: 'sns',
        state: 'FAIL',
        time: now.toISOString(),
      },
    ])
  })

  it('should report FAIL for a topic when unable to KMS keys ', async () => {
    mock('SNS', 'listTopics', {
      Topics: [
        {
          TopicArn: 'test',
        },
      ],
    })
    mock('SNS', 'getTopicAttributes', {
      Attributes: {
        KmsMasterKeyId: 'test',
      },
    })
    mock('KMS', 'describeKey', Promise.reject('test'))
    const audits = await handler({
      region: 'us-east-1',
      profile: 'test',
      domain: 'pub',
      resourceId: 'test',
      keyType: 'cmk',
    } as TopicEncryptedCliInterface)
    expect(audits).to.eql([
      {
        name: 'test',
        physicalId: 'test',
        profile: 'test',
        provider: 'aws',
        region: 'us-east-1',
        rule: 'TopicEncrypted',
        service: 'sns',
        state: 'FAIL',
        time: now.toISOString(),
      },
    ])
  })

  it('should report nothing if given the wrong key type', async () => {
    mock('SNS', 'listTopics', {
      Topics: [
        {
          TopicArn: 'test',
        },
      ],
    })
    mock('SNS', 'getTopicAttributes', {
      Attributes: {
        KmsMasterKeyId: 'test',
      },
    })
    mock('KMS', 'describeKey', {
      KeyMetadata: { Arn: 'test', KeyManager: 'CUSTOMER' },
    })
    const audits = await handler({
      region: 'us-east-1',
      profile: 'test',
      domain: 'pub',
      resourceId: 'test',
      keyType: 'test' as 'aws',
    } as TopicEncryptedCliInterface)
    expect(audits).to.eql([])
  })

  it('should report nothing for when there are no topics to scan', async () => {
    mock('SNS', 'listTopics', {})
    const audits = await handler({
      region: 'us-east-1',
      profile: 'test',
      domain: 'pub',
      keyType: 'aws',
    } as TopicEncryptedCliInterface)
    expect(audits).to.eql([])
  })
})
