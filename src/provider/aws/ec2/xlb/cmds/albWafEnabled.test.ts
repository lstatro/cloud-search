import 'mocha'
import { useFakeTimers, SinonFakeTimers } from 'sinon'
import { mock, restore } from 'aws-sdk-mock'
import { handler } from './albWafEnabled'
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

  it('should report FAIL is the alb does not have a WAF attached', async () => {
    mock('ELBv2', 'describeLoadBalancers', {
      LoadBalancers: [
        {
          LoadBalancerArn: 'test',
        },
      ],
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
        state: 'FAIL',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })
})
