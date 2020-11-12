import 'mocha'
import { useFakeTimers, SinonFakeTimers } from 'sinon'
import { mock, restore } from 'aws-sdk-mock'
import { handler } from './elbAccessLogsEnabled'
import { expect } from 'chai'

describe('elbs should log connections', () => {
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

  it('should report nothing if no elbs are found', async () => {
    mock('ELB', 'describeLoadBalancers', { LoadBalancerDescriptions: [] })

    const audits = await handler({ region: 'test', profile: 'test' })
    expect(audits).to.eql([])
  })

  it('should report nothing if no elbs are reported', async () => {
    mock('ELB', 'describeLoadBalancers', {})

    const audits = await handler({ region: 'all', profile: 'test' })
    expect(audits).to.eql([])
  })

  it('should report OK if the load balancer is logging correctly', async () => {
    mock('ELB', 'describeLoadBalancers', {
      LoadBalancerDescriptions: [
        {
          LoadBalancerName: 'test',
        },
      ],
    })

    mock('ELB', 'describeLoadBalancerAttributes', {
      LoadBalancerAttributes: {
        AccessLog: {
          Enabled: true,
          S3BucketName: 'test',
        },
      },
    })

    const audits = await handler({ region: 'test', profile: 'test' })

    expect(audits).to.eql([
      {
        provider: 'aws',
        physicalId: 'test',
        service: 'ec2',
        rule: 'ElbAccessLogsEnabled',
        region: 'test',
        state: 'OK',
        profile: 'test',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })

  it('should report FAIL if the load balancer is not logging', async () => {
    mock('ELB', 'describeLoadBalancers', {
      LoadBalancerDescriptions: [
        {
          LoadBalancerName: 'test',
        },
      ],
    })

    mock('ELB', 'describeLoadBalancerAttributes', {
      LoadBalancerAttributes: {
        AccessLog: {
          Enabled: false,
        },
      },
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
        rule: 'ElbAccessLogsEnabled',
        region: 'test',
        state: 'FAIL',
        profile: 'test',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })

  it('should report WARNING if the load balancer is logging, but w/o a s3 bucket target', async () => {
    mock('ELB', 'describeLoadBalancers', {
      LoadBalancerDescriptions: [
        {
          LoadBalancerName: 'test',
        },
      ],
    })

    mock('ELB', 'describeLoadBalancerAttributes', {
      LoadBalancerAttributes: {
        AccessLog: {
          Enabled: true,
        },
      },
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
        rule: 'ElbAccessLogsEnabled',
        region: 'test',
        state: 'WARNING',
        profile: 'test',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })

  it('should report UNKNOWN if the load balancer does not have attributes', async () => {
    mock('ELB', 'describeLoadBalancers', {
      LoadBalancerDescriptions: [
        {
          LoadBalancerName: 'test',
        },
      ],
    })

    mock('ELB', 'describeLoadBalancerAttributes', {})

    const audits = await handler({ region: 'test', profile: 'test' })

    expect(audits).to.eql([
      {
        provider: 'aws',
        physicalId: 'test',
        service: 'ec2',
        rule: 'ElbAccessLogsEnabled',
        region: 'test',
        state: 'UNKNOWN',
        profile: 'test',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })

  it('should report UNKNOWN if the load balancer does not have Access logging attributes', async () => {
    mock('ELB', 'describeLoadBalancers', {
      LoadBalancerDescriptions: [
        {
          LoadBalancerName: 'test',
        },
      ],
    })

    mock('ELB', 'describeLoadBalancerAttributes', {
      LoadBalancerAttributes: {},
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
        rule: 'ElbAccessLogsEnabled',
        region: 'test',
        state: 'UNKNOWN',
        profile: 'test',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })
})
