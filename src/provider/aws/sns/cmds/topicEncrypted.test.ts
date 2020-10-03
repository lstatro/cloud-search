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

  it('should report OK for encrypted topics', async () => {
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

  it('should handle single resource requests', async () => {
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
    const audits = await handler({
      region: 'us-east-1',
      profile: 'test',
      domain: 'pub',
      resourceId: 'test',
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
})
