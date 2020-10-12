import 'mocha'
import { expect } from 'chai'
import { useFakeTimers, SinonFakeTimers } from 'sinon'
import { mock, restore } from 'aws-sdk-mock'
import { handler } from './publicRole'
import { AWSScannerInterface } from 'cloud-search'

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

  it('should report nothing if no roles are found', async () => {
    mock('IAM', 'listRoles', {
      Roles: [],
    })

    let audits

    audits = await handler({
      profile: 'test',
    } as AWSScannerInterface)
    expect(audits).to.eql([])

    restore()

    mock('EC2', 'describeRegions', { Regions: [{ RegionName: 'us-east-1' }] })
    mock('IAM', 'listRoles', {})

    audits = await handler({
      profile: 'test',
    } as AWSScannerInterface)
    expect(audits).to.eql([])
  })

  it('should report OK if a role does not have * in its principal string', async () => {
    mock('IAM', 'getRole', {
      Role: {
        AssumeRolePolicyDocument: encodeURIComponent(
          JSON.stringify({
            Statement: [
              {
                Principal: {
                  AWS: 'test',
                },
              },
            ],
          })
        ),
      },
    })

    const audits = await handler({
      profile: 'test',
      resourceId: 'test',
    } as AWSScannerInterface)
    expect(audits).to.eql([
      {
        physicalId: 'test',
        profile: 'test',
        provider: 'aws',
        region: 'global',
        rule: 'PublicRole',
        service: 'iam',
        state: 'OK',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })

  it('should report OK if a role does not have * in its principal string (scan)', async () => {
    mock('IAM', 'listRoles', {
      Roles: [
        {
          RoleName: 'test',
          AssumeRolePolicyDocument: encodeURIComponent(
            JSON.stringify({
              Statement: [
                {
                  Principal: {
                    AWS: 'test',
                  },
                },
              ],
            })
          ),
        },
      ],
    })

    const audits = await handler({
      profile: 'test',
    } as AWSScannerInterface)
    expect(audits).to.eql([
      {
        physicalId: 'test',
        profile: 'test',
        provider: 'aws',
        region: 'global',
        rule: 'PublicRole',
        service: 'iam',
        state: 'OK',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })

  it('should report FAIL if a role has * in its principal string (scan)', async () => {
    mock('IAM', 'listRoles', {
      Roles: [
        {
          RoleName: 'test',
          AssumeRolePolicyDocument: encodeURIComponent(
            JSON.stringify({
              Statement: [
                {
                  Principal: {
                    AWS: '*',
                  },
                },
              ],
            })
          ),
        },
      ],
    })

    const audits = await handler({
      profile: 'test',
    } as AWSScannerInterface)
    expect(audits).to.eql([
      {
        physicalId: 'test',
        profile: 'test',
        provider: 'aws',
        region: 'global',
        rule: 'PublicRole',
        service: 'iam',
        state: 'FAIL',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })

  it('should report FAIL fail if there is a * in a principal array', async () => {
    mock('IAM', 'listRoles', {
      Roles: [
        {
          RoleName: 'test',
          AssumeRolePolicyDocument: encodeURIComponent(
            JSON.stringify({
              Statement: [
                {
                  Principal: {
                    AWS: ['test', 'test', '*'],
                  },
                },
              ],
            })
          ),
        },
      ],
    })

    const audits = await handler({
      profile: 'test',
    } as AWSScannerInterface)
    expect(audits).to.eql([
      {
        physicalId: 'test',
        profile: 'test',
        provider: 'aws',
        region: 'global',
        rule: 'PublicRole',
        service: 'iam',
        state: 'FAIL',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })

  it('should report WARNING fail if there is a * and a condition in a principal array', async () => {
    mock('IAM', 'listRoles', {
      Roles: [
        {
          RoleName: 'test',
          AssumeRolePolicyDocument: encodeURIComponent(
            JSON.stringify({
              Statement: [
                {
                  Principal: {
                    AWS: ['test', 'test', '*'],
                  },
                  Condition: 'test',
                },
              ],
            })
          ),
        },
      ],
    })

    const audits = await handler({
      profile: 'test',
    } as AWSScannerInterface)
    expect(audits).to.eql([
      {
        physicalId: 'test',
        profile: 'test',
        provider: 'aws',
        region: 'global',
        rule: 'PublicRole',
        service: 'iam',
        state: 'WARNING',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })

  it('should report OK there is no AWS principal in any of the statements', async () => {
    mock('IAM', 'listRoles', {
      Roles: [
        {
          RoleName: 'test',
          AssumeRolePolicyDocument: encodeURIComponent(
            JSON.stringify({
              Statement: [
                {
                  Principal: {
                    Service: 'test',
                  },
                  Condition: 'test',
                },
              ],
            })
          ),
        },
      ],
    })

    const audits = await handler({
      profile: 'test',
    } as AWSScannerInterface)
    expect(audits).to.eql([
      {
        physicalId: 'test',
        profile: 'test',
        provider: 'aws',
        region: 'global',
        rule: 'PublicRole',
        service: 'iam',
        state: 'OK',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })
})
