import 'mocha'
import { useFakeTimers, SinonFakeTimers } from 'sinon'
import { mock, restore } from 'aws-sdk-mock'
import { handler } from './elbDesyncMode'
import { expect } from 'chai'

describe('elbs should have desync mode set to strict', () => {
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

  it('should report OK if an elbs desync mode is set to strict', async () => {
    mock('ELB', 'describeLoadBalancers', {
      LoadBalancerDescriptions: [
        {
          LoadBalancerName: 'test',
        },
      ],
    })

    mock('ELB', 'describeLoadBalancerAttributes', {
      LoadBalancerAttributes: {
        AdditionalAttributes: [
          {
            Key: 'test-desyncmitigationmode',
            Value: 'strictest',
          },
        ],
      },
    })

    const audits = await handler({ region: 'all', profile: 'test' })
    expect(audits).to.eql([
      {
        physicalId: 'test',
        profile: 'test',
        provider: 'aws',
        region: 'us-east-1',
        rule: 'ElbDesyncMode',
        service: 'ec2',
        state: 'OK',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })

  it('should report FAIL if no load balancer attributes are found', async () => {
    mock('ELB', 'describeLoadBalancers', {
      LoadBalancerDescriptions: [
        {
          LoadBalancerName: 'test',
        },
      ],
    })

    mock('ELB', 'describeLoadBalancerAttributes', {})

    const audits = await handler({ region: 'all', profile: 'test' })
    expect(audits).to.eql([
      {
        physicalId: 'test',
        profile: 'test',
        provider: 'aws',
        region: 'us-east-1',
        rule: 'ElbDesyncMode',
        service: 'ec2',
        state: 'FAIL',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })

  it('should report FAIL if there are no additional lb attributes', async () => {
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

    const audits = await handler({ region: 'all', profile: 'test' })
    expect(audits).to.eql([
      {
        physicalId: 'test',
        profile: 'test',
        provider: 'aws',
        region: 'us-east-1',
        rule: 'ElbDesyncMode',
        service: 'ec2',
        state: 'FAIL',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })

  it('should report FAIL if there there is no value in additional attributes', async () => {
    mock('ELB', 'describeLoadBalancers', {
      LoadBalancerDescriptions: [
        {
          LoadBalancerName: 'test',
        },
      ],
    })

    mock('ELB', 'describeLoadBalancerAttributes', {
      LoadBalancerAttributes: {
        AdditionalAttributes: [
          {
            Key: 'test-desyncmitigationmode',
          },
        ],
      },
    })

    const audits = await handler({ region: 'all', profile: 'test' })
    expect(audits).to.eql([
      {
        physicalId: 'test',
        profile: 'test',
        provider: 'aws',
        region: 'us-east-1',
        rule: 'ElbDesyncMode',
        service: 'ec2',
        state: 'FAIL',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })

  it('should report FAIL if there there is no key in additional attributes', async () => {
    mock('ELB', 'describeLoadBalancers', {
      LoadBalancerDescriptions: [
        {
          LoadBalancerName: 'test',
        },
      ],
    })

    mock('ELB', 'describeLoadBalancerAttributes', {
      LoadBalancerAttributes: {
        AdditionalAttributes: [
          {
            Value: 'strictest',
          },
        ],
      },
    })

    const audits = await handler({ region: 'all', profile: 'test' })
    expect(audits).to.eql([
      {
        physicalId: 'test',
        profile: 'test',
        provider: 'aws',
        region: 'us-east-1',
        rule: 'ElbDesyncMode',
        service: 'ec2',
        state: 'FAIL',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })

  it('should report FAIL if there is no desync attribute', async () => {
    mock('ELB', 'describeLoadBalancers', {
      LoadBalancerDescriptions: [
        {
          LoadBalancerName: 'test',
        },
      ],
    })

    mock('ELB', 'describeLoadBalancerAttributes', {
      LoadBalancerAttributes: {
        AdditionalAttributes: [
          {
            Key: 'test',
          },
        ],
      },
    })

    const audits = await handler({
      region: 'us-east-1',
      profile: 'test',
      resourceId: 'test',
    })

    expect(audits).to.eql([
      {
        physicalId: 'test',
        profile: 'test',
        provider: 'aws',
        region: 'us-east-1',
        rule: 'ElbDesyncMode',
        service: 'ec2',
        state: 'FAIL',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })

  it('should report UNKNOWN if the desync attribute is not one of the three expected types', async () => {
    mock('ELB', 'describeLoadBalancers', {
      LoadBalancerDescriptions: [
        {
          LoadBalancerName: 'test',
        },
      ],
    })

    mock('ELB', 'describeLoadBalancerAttributes', {
      LoadBalancerAttributes: {
        AdditionalAttributes: [
          {
            Key: 'test-desyncmitigationmode',
            Value: 'test',
          },
        ],
      },
    })

    const audits = await handler({
      region: 'us-east-1',
      profile: 'test',
      resourceId: 'test',
    })

    expect(audits).to.eql([
      {
        physicalId: 'test',
        profile: 'test',
        provider: 'aws',
        region: 'us-east-1',
        rule: 'ElbDesyncMode',
        service: 'ec2',
        state: 'UNKNOWN',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })
})
