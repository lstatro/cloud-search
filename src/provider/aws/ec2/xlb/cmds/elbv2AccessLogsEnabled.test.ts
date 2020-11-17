import 'mocha'
import { useFakeTimers, SinonFakeTimers } from 'sinon'
import { mock, restore } from 'aws-sdk-mock'
import { handler as alb } from './albAccessLogsEnabled'
import { handler as nlb } from './nlbAccessLogsEnabled'
import { Elbv2AccessLogsEnabled } from './elbv2AccessLogsEnabled'
import { expect } from 'chai'

describe('elbv2 load balancers should log connections', () => {
  const now = new Date(0)
  let clock: SinonFakeTimers

  beforeEach(() => {
    clock = useFakeTimers(now)
    mock('EC2', 'describeRegions', {
      Regions: [{ RegionName: 'us-east-1' }],
    })
  })

  afterEach(() => {
    clock.restore()
    restore()
  })

  describe('should not handle', () => {
    it('should not report anything for unknown lb types', async () => {
      mock('ELBv2', 'describeLoadBalancers', {
        LoadBalancers: [
          {
            Type: 'application',
            LoadBalancerArn: 'test',
          },
        ],
      })

      const scanner = await new Elbv2AccessLogsEnabled({
        region: 'us-east-1',
        rule: 'AlbAccessLogsEnabled',
        type: 'test' as 'network',
      })

      await scanner.start()

      expect(scanner.audits).to.eql([])
    })
  })

  describe('should handle', () => {
    const params = [
      { handler: alb, type: 'application', rule: 'AlbAccessLogsEnabled' },
      { handler: nlb, type: 'network', rule: 'NlbAccessLogsEnabled' },
    ]

    for (const { handler, type, rule } of params) {
      it(`should report nothing if no ${type} lbs are found`, async () => {
        mock('ELBv2', 'describeLoadBalancers', { LoadBalancerDescriptions: [] })
        const audits = await handler({ region: 'test', profile: 'test' })
        expect(audits).to.eql([])
      })

      it(`should report nothing if no ${type} lbs are reported`, async () => {
        mock('ELBv2', 'describeLoadBalancers', {})

        const audits = await handler({ region: 'all', profile: 'test' })
        expect(audits).to.eql([])
      })

      it(`should report nothing if the ${type} type is not found`, async () => {
        mock('ELBv2', 'describeLoadBalancers', {
          LoadBalancers: [
            {
              Type: 'test',
              LoadBalancerArn: 'test',
            },
          ],
        })

        const audits = await handler({ region: 'test', profile: 'test' })

        expect(audits).to.eql([])
      })

      it(`should report OK if the ${type} lber is logging correctly`, async () => {
        mock('ELBv2', 'describeLoadBalancers', {
          LoadBalancers: [
            {
              Type: type,
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
            rule,
            region: 'test',
            state: 'OK',
            profile: 'test',
            time: '1970-01-01T00:00:00.000Z',
          },
        ])
      })

      it(`should report UNKNOWN if the ${type} lber has no attributes`, async () => {
        mock('ELBv2', 'describeLoadBalancers', {
          LoadBalancers: [
            {
              Type: type,
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
            rule,
            region: 'test',
            state: 'UNKNOWN',
            profile: 'test',
            time: '1970-01-01T00:00:00.000Z',
          },
        ])
      })

      it(`should report WARNING if the ${type} lber is logging but does not have a target bucket`, async () => {
        mock('ELBv2', 'describeLoadBalancers', {
          LoadBalancers: [
            {
              Type: type,
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
            rule,
            region: 'test',
            state: 'WARNING',
            profile: 'test',
            time: '1970-01-01T00:00:00.000Z',
          },
        ])
      })

      it(`should report FAIL if the ${type} lb is not logging`, async () => {
        mock('ELBv2', 'describeLoadBalancers', {
          LoadBalancers: [
            {
              Type: type,
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
            rule,
            region: 'test',
            state: 'FAIL',
            profile: 'test',
            time: '1970-01-01T00:00:00.000Z',
          },
        ])
      })
    }
  })
})
