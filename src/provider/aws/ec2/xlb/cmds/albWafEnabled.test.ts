import { SinonFakeTimers, useFakeTimers } from 'sinon'
import { mock, restore } from 'aws-sdk-mock'

import { expect } from 'chai'
import { handler } from './albWafEnabled'

describe('albs have a WAF attached', () => {
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

  it('should report FAIL if the alb does not have a WAF attached', async () => {
    mock('ELBv2', 'describeLoadBalancers', {
      LoadBalancers: [
        {
          LoadBalancerArn: 'test',
        },
      ],
    })

    mock('WAFV2', 'getWebACLForResource', {})

    mock('WAFRegional', 'getWebACLForResource', {})

    const audits = await handler({ region: 'all', profile: 'test' })

    expect(audits).to.eql([
      {
        physicalId: 'test',
        profile: 'test',
        provider: 'aws',
        region: 'us-east-1',
        rule: 'AlbWafEnabled',
        service: 'ec2',
        state: 'FAIL',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })

  it('should report OK if the alb has a classic WAF attached', async () => {
    mock('ELBv2', 'describeLoadBalancers', {
      LoadBalancers: [
        {
          LoadBalancerArn: 'test',
        },
      ],
    })

    mock('WAFV2', 'getWebACLForResource', {})

    mock('WAFRegional', 'getWebACLForResource', {
      WebACLSummary: {
        Name: 'test',
      },
    })

    const audits = await handler({ region: 'all', profile: 'test' })

    expect(audits).to.eql([
      {
        physicalId: 'test',
        profile: 'test',
        provider: 'aws',
        region: 'us-east-1',
        rule: 'AlbWafEnabled',
        service: 'ec2',
        state: 'OK',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })

  it('should report OK if the alb has a V2 WAF attached', async () => {
    mock('ELBv2', 'describeLoadBalancers', {
      LoadBalancers: [
        {
          LoadBalancerArn: 'test',
        },
      ],
    })

    mock('WAFV2', 'getWebACLForResource', { WebACL: { Name: 'test' } })

    mock('WAFRegional', 'getWebACLForResource', {})

    const audits = await handler({
      region: 'test',
      profile: 'test',
      resource: 'test',
    })

    expect(audits).to.eql([
      {
        physicalId: 'test',
        profile: 'test',
        provider: 'aws',
        region: 'test',
        rule: 'AlbWafEnabled',
        service: 'ec2',
        state: 'OK',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })
})
