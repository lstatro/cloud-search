import { SinonFakeTimers, useFakeTimers } from 'sinon'
import { mock, restore } from 'aws-sdk-mock'

import { expect } from 'chai'
import { handler } from './hasManagedAdmin'

describe('groups should not have managed admin attached', () => {
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

  it('should report nothing if no groups are found', async () => {
    mock('IAM', 'listGroups', {})

    const audits = await handler({
      region: 'all',
      profile: 'test',
    })
    expect(audits).to.eql([])
  })

  it('should report nothing if no groups are reported', async () => {
    mock('IAM', 'listGroups', { Groups: [] })

    const audits = await handler({
      region: 'all',
      profile: 'test',
    })
    expect(audits).to.eql([])
  })

  it('should report OK if a group does not have admin attached', async () => {
    mock('IAM', 'listGroups', {
      Groups: [
        {
          GroupName: 'test',
        },
      ],
    })

    mock('IAM', 'listAttachedGroupPolicies', {
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
        region: 'global',
        rule: 'HasManagedAdmin',
        service: 'iam',
        state: 'OK',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })

  it('should report OK if a group has no attached policy', async () => {
    mock('IAM', 'listGroups', {
      Groups: [
        {
          GroupName: 'test',
        },
      ],
    })

    mock('IAM', 'listAttachedGroupPolicies', {})

    const audits = await handler({
      region: 'all',
      profile: 'test',
    })

    expect(audits).to.eql([
      {
        physicalId: 'test',
        profile: 'test',
        provider: 'aws',
        region: 'global',
        rule: 'HasManagedAdmin',
        service: 'iam',
        state: 'OK',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })

  it('should report FAIL if a group has no attached policy', async () => {
    mock('IAM', 'listGroups', {
      Groups: [
        {
          GroupName: 'test',
        },
      ],
    })

    mock('IAM', 'listAttachedGroupPolicies', {
      AttachedPolicies: [
        {
          PolicyName: 'AdministratorAccess',
        },
      ],
    })

    const audits = await handler({
      region: 'us-east-1',
      resource: 'test',
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

  it('should report OK if a group has managed policy attached, but it is not admin', async () => {
    mock('IAM', 'listGroups', {
      Users: [
        {
          UserName: 'test',
        },
      ],
    })

    mock('IAM', 'listAttachedGroupPolicies', {
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
      resource: 'test',
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
