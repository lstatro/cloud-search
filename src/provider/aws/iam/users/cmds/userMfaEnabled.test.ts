import { SinonFakeTimers, restore as sinonRestore, useFakeTimers } from 'sinon'
import { mock, restore } from 'aws-sdk-mock'

import { expect } from 'chai'
import { handler } from './userMfaEnabled'

describe('users should have MFA enabled', () => {
  const now = new Date(0)
  let clock: SinonFakeTimers

  beforeEach(() => {
    clock = useFakeTimers(now)
    mock('EC2', 'describeRegions', { Regions: [{ RegionName: 'us-east-1' }] })
  })

  afterEach(() => {
    clock.restore()
    restore()
    sinonRestore()
  })

  it('should report nothing if listUsers does not have Users attribute', async () => {
    mock('IAM', 'listUsers', {})

    const audits = await handler({ region: 'us-east-1' })
    expect(audits).to.eql([])
  })

  it('should report nothing if the listUsers returns an empty array of Users', async () => {
    mock('IAM', 'listUsers', { Users: [] })

    const audits = await handler({ region: 'us-east-1' })
    expect(audits).to.eql([])
  })

  it('should report FAIL if a user has no MFA devices attached', async () => {
    mock('IAM', 'listUsers', {
      Users: [
        {
          UserName: 'test',
        },
      ],
    })

    mock('IAM', 'listMFADevices', {
      MFADevices: [],
    })

    const audits = await handler({ region: 'us-east-1' })
    expect(audits).to.eql([
      {
        physicalId: 'test',
        profile: undefined,
        provider: 'aws',
        region: 'us-east-1',
        rule: 'UserMfaEnabled',
        service: 'iam',
        state: 'FAIL',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })

  it('should report OK if a user has one MFA device attached', async () => {
    mock('IAM', 'listUsers', {
      Users: [
        {
          UserName: 'test',
        },
      ],
    })

    mock('IAM', 'listMFADevices', {
      MFADevices: [
        {
          UserName: 'test',
          SerialNumber: 'test',
          EnableDate: 'test',
        },
      ],
    })

    const audits = await handler({ region: 'us-east-1', resource: 'test' })
    expect(audits).to.eql([
      {
        physicalId: 'test',
        profile: undefined,
        provider: 'aws',
        region: 'us-east-1',
        rule: 'UserMfaEnabled',
        service: 'iam',
        state: 'OK',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })
})
