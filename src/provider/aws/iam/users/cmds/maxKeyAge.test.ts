import { mock, restore } from 'aws-sdk-mock'
import { handler } from './maxKeyAge'
import { expect } from 'chai'

describe('iam keys should not be older then a specific age', () => {
  beforeEach(() => {
    mock('EC2', 'describeRegions', { Regions: [{ RegionName: 'us-east-1' }] })
  })

  afterEach(() => {
    restore()
  })

  it('should report OK', async () => {
    mock('IAM', 'listUsers', {
      Users: [
        {
          UserName: 'test',
        },
      ],
    })
    mock('IAM', 'listAccessKeys', {
      AccessKeyMetadata: [
        {
          AccessKeyId: 'test',
          CreateDate: new Date(),
        },
      ],
    })
    const audits = await handler({
      resourceId: 'test',
      region: 'test',
      maxAge: 30,
      profile: 'test',
    })

    expect(audits[0].state).to.eql('OK')
  })

  it('should report nothing if no users are reported', async () => {
    mock('IAM', 'listUsers', {})
    mock('IAM', 'listAccessKeys', {
      AccessKeyMetadata: [
        {
          AccessKeyId: 'test',
          CreateDate: new Date(),
        },
      ],
    })
    const audits = await handler({
      resourceId: 'test',
      region: 'test',
      maxAge: 30,
      profile: 'test',
    })

    expect(audits).to.eql([])
  })

  it('should report error', async () => {
    mock('IAM', 'listUsers', {
      Users: [
        {
          UserName: 'test',
        },
      ],
    })
    mock('IAM', 'listAccessKeys', {
      AccessKeyMetadata: [
        {
          AccessKeyId: 'test',
          CreateDate: new Date(0),
        },
      ],
    })
    const audits = await handler({
      resourceId: 'test',
      region: 'test',
      maxAge: 30,
      profile: 'test',
    })

    expect(audits[0].state).to.eql('FAIL')
  })

  it('should handle users without keys', async () => {
    mock('IAM', 'listUsers', {
      Users: [
        {
          UserName: 'test',
        },
      ],
    })
    mock('IAM', 'listAccessKeys', {})
    const audits = await handler({
      resourceId: 'test',
      region: 'test',
      maxAge: 30,
      profile: 'test',
    })
    expect(audits[0].state).to.eql('OK')
  })

  it('should handle no users', async () => {
    mock('IAM', 'listUsers', {})
    const audits = await handler({
      region: 'all',
      maxAge: 30,
      profile: 'test',
    })
    expect(audits).to.eql([])
  })
})
