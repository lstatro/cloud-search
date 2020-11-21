import 'chai'
import { useFakeTimers, SinonFakeTimers } from 'sinon'
import { mock, restore } from 'aws-sdk-mock'
import { handler } from './publicPermission'
import { expect } from 'chai'

/** none of these tests should throw */

describe('security group with a public permission', () => {
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

  it('should report FAIL if there is a public permission', async () => {
    mock('EC2', 'describeSecurityGroups', {
      SecurityGroups: [
        {
          GroupId: 'test',
          IpPermissions: [
            {
              IpRanges: [
                {
                  CidrIp: '0.0.0.0/0',
                },
              ],
            },
          ],
        },
      ],
    })
    const audits = await handler({
      region: 'us-east-1',
      profile: 'test',
      resourceId: 'test',
    })
    expect(audits).to.eql([
      {
        name: undefined,
        provider: 'aws',
        physicalId: 'test',
        service: 'ec2',
        rule: 'PublicPermission',
        region: 'us-east-1',
        state: 'FAIL',
        profile: 'test',
        time: now.toISOString(),
      },
    ])
  })

  it('should report OK if it is not 0.0.0.0/0', async () => {
    mock('EC2', 'describeSecurityGroups', {
      SecurityGroups: [
        {
          GroupId: 'test',
          IpPermissions: [
            {
              IpRanges: [
                {
                  CidrIp: '10.0.0.0/16',
                },
              ],
            },
          ],
        },
      ],
    })
    const audits = await handler({
      region: 'us-east-1',
      profile: 'test',
      resourceId: 'test',
    })
    expect(audits).to.eql([
      {
        name: undefined,
        provider: 'aws',
        physicalId: 'test',
        service: 'ec2',
        rule: 'PublicPermission',
        region: 'us-east-1',
        state: 'OK',
        profile: 'test',
        time: now.toISOString(),
      },
    ])
  })

  it('should report OK if it is not 0.0.0.0/0 without a resourceId', async () => {
    mock('EC2', 'describeSecurityGroups', {
      SecurityGroups: [
        {
          GroupId: 'test',
          IpPermissions: [
            {
              IpRanges: [
                {
                  CidrIp: '10.0.0.0/16',
                },
              ],
            },
          ],
        },
      ],
    })
    const audits = await handler({
      profile: 'test',
      region: 'all',
    })
    expect(audits).to.eql([
      {
        name: undefined,
        provider: 'aws',
        physicalId: 'test',
        service: 'ec2',
        rule: 'PublicPermission',
        region: 'us-east-1',
        state: 'OK',
        profile: 'test',
        time: now.toISOString(),
      },
    ])
  })

  it('should report OK if there are no ipRanges', async () => {
    mock('EC2', 'describeSecurityGroups', {
      SecurityGroups: [
        {
          GroupId: 'test',
          IpPermissions: [{}],
        },
      ],
    })
    const audits = await handler({
      region: 'us-east-1',
      profile: 'test',
      resourceId: 'test',
    })
    expect(audits).to.eql([
      {
        name: undefined,
        provider: 'aws',
        physicalId: 'test',
        service: 'ec2',
        rule: 'PublicPermission',
        region: 'us-east-1',
        state: 'OK',
        profile: 'test',
        time: now.toISOString(),
      },
    ])
  })

  it('should report OK if there are no IpPermissions', async () => {
    mock('EC2', 'describeSecurityGroups', {
      SecurityGroups: [
        {
          GroupId: 'test',
        },
      ],
    })
    const audits = await handler({
      region: 'us-east-1',
      profile: 'test',
      resourceId: 'test',
    })
    expect(audits).to.eql([
      {
        name: undefined,
        provider: 'aws',
        physicalId: 'test',
        service: 'ec2',
        rule: 'PublicPermission',
        region: 'us-east-1',
        state: 'OK',
        profile: 'test',
        time: now.toISOString(),
      },
    ])
  })

  it('should report FAIL if there ::/0 is permitted', async () => {
    mock('EC2', 'describeSecurityGroups', {
      SecurityGroups: [
        {
          GroupId: 'test',
          IpPermissions: [
            {
              Ipv6Ranges: [
                {
                  CidrIpv6: '::/0',
                },
              ],
            },
          ],
        },
      ],
    })
    const audits = await handler({
      region: 'us-east-1',
      profile: 'test',
      resourceId: 'test',
    })
    expect(audits).to.eql([
      {
        name: undefined,
        provider: 'aws',
        physicalId: 'test',
        service: 'ec2',
        rule: 'PublicPermission',
        region: 'us-east-1',
        state: 'FAIL',
        profile: 'test',
        time: now.toISOString(),
      },
    ])
  })

  it('should report FAIL if there ::/0 is not permitted', async () => {
    mock('EC2', 'describeSecurityGroups', {
      SecurityGroups: [
        {
          GroupId: 'test',
          IpPermissions: [
            {
              Ipv6Ranges: [
                {
                  CidrIpv6: '1:see:bad:c0de/128',
                },
              ],
            },
          ],
        },
      ],
    })
    const audits = await handler({
      region: 'us-east-1',
      profile: 'test',
      resourceId: 'test',
    })
    expect(audits).to.eql([
      {
        name: undefined,
        provider: 'aws',
        physicalId: 'test',
        service: 'ec2',
        rule: 'PublicPermission',
        region: 'us-east-1',
        state: 'OK',
        profile: 'test',
        time: now.toISOString(),
      },
    ])
  })

  it('should report nothing if there are no security groups', async () => {
    mock('EC2', 'describeSecurityGroups', {})
    const audits = await handler({
      region: 'us-east-1',
      profile: 'test',
      resourceId: 'test',
    })
    expect(audits).to.eql([])
  })

  it('should throw if the describe groups fails for an unknown reason', async () => {
    class Err extends Error {
      code = 'potato'
    }
    const myErr = new Err('test error')
    mock('EC2', 'describeSecurityGroups', Promise.reject(myErr))
    let audits
    try {
      audits = await handler({
        region: 'us-east-1',
        profile: 'test',
        resourceId: 'test',
      })
    } catch (err) {
      audits = err
    }

    expect(audits instanceof Error).to.be.true
  })
})
