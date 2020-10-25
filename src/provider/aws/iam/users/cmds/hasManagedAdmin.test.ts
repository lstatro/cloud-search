import 'mocha'
import { mock, restore } from 'aws-sdk-mock'
import { useFakeTimers, SinonFakeTimers } from 'sinon'
import { handler } from './hasManagedAdmin'
import { expect } from 'chai'

describe('passwordAge', () => {
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

  it('should report nothing if no users are found', async () => {
    mock('IAM', 'listUsers', {})

    const audits = await handler({
      region: 'all',
      profile: 'test',
    })
    expect(audits).to.eql([])
  })

  it('should report nothing if no users are reported', async () => {
    mock('IAM', 'listUsers', { Users: [] })

    const audits = await handler({
      region: 'all',
      profile: 'test',
    })
    expect(audits).to.eql([])
  })

  it('should report OK if a user does not have admin attached', async () => {
    mock('IAM', 'listUsers', {
      Users: [
        {
          UserName: 'test',
        },
      ],
    })

    mock('IAM', 'listAttachedUserPolicies', {
      AttachedPolicies: [],
    })

    const audits = await handler({
      region: 'all',
      profile: 'test',
    })
    expect(audits).to.eql([
      {
        physicalId: 'test',
        profile: 'test',
        provider: 'aws',
        region: 'all',
        rule: 'HasManagedAdmin',
        service: 'iam',
        state: 'OK',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })

  it('should report OK if a user has no attached policy', async () => {
    mock('IAM', 'listUsers', {
      Users: [
        {
          UserName: 'test',
        },
      ],
    })

    mock('IAM', 'listAttachedUserPolicies', {})

    const audits = await handler({
      region: 'all',
      profile: 'test',
    })
    expect(audits).to.eql([
      {
        physicalId: 'test',
        profile: 'test',
        provider: 'aws',
        region: 'all',
        rule: 'HasManagedAdmin',
        service: 'iam',
        state: 'OK',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })

  it('should report FAIL if a user has no attached policy', async () => {
    mock('IAM', 'listUsers', {
      Users: [
        {
          UserName: 'test',
        },
      ],
    })

    mock('IAM', 'listAttachedUserPolicies', {
      AttachedPolicies: [
        {
          PolicyName: 'AdministratorAccess',
        },
      ],
    })

    const audits = await handler({
      region: 'us-east-1',
      resourceId: 'test',
      profile: 'test',
    })
    expect(audits).to.eql([
      {
        physicalId: 'test',
        profile: 'test',
        provider: 'aws',
        region: 'us-east-1',
        rule: 'HasManagedAdmin',
        service: 'iam',
        state: 'FAIL',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })

  it('should report OK if a user has managed policy attached, but it is not admin', async () => {
    mock('IAM', 'listUsers', {
      Users: [
        {
          UserName: 'test',
        },
      ],
    })

    mock('IAM', 'listAttachedUserPolicies', {
      AttachedPolicies: [
        {
          PolicyName: 'MyTest1',
        },
        {
          PolicyName: 'MyTest2',
        },
      ],
    })

    const audits = await handler({
      region: 'us-east-1',
      resourceId: 'test',
      profile: 'test',
    })
    expect(audits).to.eql([
      {
        physicalId: 'test',
        profile: 'test',
        provider: 'aws',
        region: 'us-east-1',
        rule: 'HasManagedAdmin',
        service: 'iam',
        state: 'OK',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })
})
