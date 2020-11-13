import 'mocha'
import { useFakeTimers, SinonFakeTimers } from 'sinon'
import { mock, restore } from 'aws-sdk-mock'
import { handler } from './albAccessLogsEnabled'
import { expect } from 'chai'

describe('albs should log connections', () => {
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

  it('should report nothing if no albs are found', async () => {
    mock('ELBv2', 'describeLoadBalancers', { LoadBalancerDescriptions: [] })

    const audits = await handler({ region: 'test', profile: 'test' })
    expect(audits).to.eql([])
  })

  it('should report nothing if no albs are reported', async () => {
    mock('ELBv2', 'describeLoadBalancers', {})

    const audits = await handler({ region: 'all', profile: 'test' })
    expect(audits).to.eql([])
  })

  it('should report OK if the alb is logging correctly', async () => {
    mock('ELBv2', 'describeLoadBalancers', {
      LoadBalancers: [
        {
          LoadBalancerArn: 'test',
        },
      ],
    })

    mock('ELBv2', 'describeLoadBalancerAttributes', {
      Attributes: [
        {
          Key: 'access_logs.s3.enabled',
          Value: 'true',
        },
        {
          Key: 'access_logs.s3.bucket',
          Value: 'test',
        },
      ],
    })

    const audits = await handler({ region: 'test', profile: 'test' })

    expect(audits).to.eql([
      {
        provider: 'aws',
        physicalId: 'test',
        service: 'ec2',
        rule: 'AlbAccessLogsEnabled',
        region: 'test',
        state: 'OK',
        profile: 'test',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })

  it('should report UNKNOWN if the alb has no attributes', async () => {
    mock('ELBv2', 'describeLoadBalancers', {
      LoadBalancers: [
        {
          LoadBalancerArn: 'test',
        },
      ],
    })

    mock('ELBv2', 'describeLoadBalancerAttributes', {})

    const audits = await handler({ region: 'test', profile: 'test' })

    expect(audits).to.eql([
      {
        provider: 'aws',
        physicalId: 'test',
        service: 'ec2',
        rule: 'AlbAccessLogsEnabled',
        region: 'test',
        state: 'UNKNOWN',
        profile: 'test',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })

  it('should report WARNING if the alb is logging but does not have a target bucket', async () => {
    mock('ELBv2', 'describeLoadBalancers', {
      LoadBalancers: [
        {
          LoadBalancerArn: 'test',
        },
      ],
    })

    mock('ELBv2', 'describeLoadBalancerAttributes', {
      Attributes: [
        {
          Key: 'access_logs.s3.enabled',
          Value: 'true',
        },
        {
          Key: 'access_logs.s3.bucket',
        },
      ],
    })

    const audits = await handler({ region: 'test', profile: 'test' })

    expect(audits).to.eql([
      {
        provider: 'aws',
        physicalId: 'test',
        service: 'ec2',
        rule: 'AlbAccessLogsEnabled',
        region: 'test',
        state: 'WARNING',
        profile: 'test',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })

  it('should report FAIL if the alb is not logging', async () => {
    mock('ELBv2', 'describeLoadBalancers', {
      LoadBalancers: [
        {
          LoadBalancerArn: 'test',
        },
      ],
    })

    mock('ELBv2', 'describeLoadBalancerAttributes', {
      Attributes: [
        {
          Key: 'access_logs.s3.enabled',
          Value: 'false',
        },
      ],
    })

    const audits = await handler({
      region: 'test',
      profile: 'test',
      resourceId: 'test',
    })

    expect(audits).to.eql([
      {
        provider: 'aws',
        physicalId: 'test',
        service: 'ec2',
        rule: 'AlbAccessLogsEnabled',
        region: 'test',
        state: 'FAIL',
        profile: 'test',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })
})
