import 'chai'
import { useFakeTimers, SinonFakeTimers } from 'sinon'
import { mock, restore } from 'aws-sdk-mock'
import { handler } from './igwAttachedToVpc'
import { expect } from 'chai'

describe('igw vpc attachment', () => {
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

  it('should report FAIL if the gateway is attached', async () => {
    mock('EC2', 'describeInternetGateways', {
      InternetGateways: [
        {
          InternetGatewayId: 'test',
          Attachments: [
            {
              State: 'available',
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
        provider: 'aws',
        physicalId: 'test',
        service: 'ec2',
        rule: 'IgwAttachedToVpc',
        region: 'us-east-1',
        state: 'FAIL',
        profile: 'test',
        time: now.toISOString(),
      },
    ])
  })

  it('should report OK if the state does not indicate its ready', async () => {
    mock('EC2', 'describeInternetGateways', {
      InternetGateways: [
        {
          InternetGatewayId: 'test',
          Attachments: [
            {
              State: 'test',
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
        provider: 'aws',
        physicalId: 'test',
        service: 'ec2',
        rule: 'IgwAttachedToVpc',
        region: 'us-east-1',
        state: 'OK',
        profile: 'test',
        time: now.toISOString(),
      },
    ])
  })

  it('should report OK if there is not attachment state', async () => {
    mock('EC2', 'describeInternetGateways', {
      InternetGateways: [
        {
          InternetGatewayId: 'test',
          Attachments: [{}],
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
        provider: 'aws',
        physicalId: 'test',
        service: 'ec2',
        rule: 'IgwAttachedToVpc',
        region: 'us-east-1',
        state: 'OK',
        profile: 'test',
        time: now.toISOString(),
      },
    ])
  })

  it('should report OK if there are no attachments state objects', async () => {
    mock('EC2', 'describeInternetGateways', {
      InternetGateways: [
        {
          InternetGatewayId: 'test',
          Attachments: [],
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
        provider: 'aws',
        physicalId: 'test',
        service: 'ec2',
        rule: 'IgwAttachedToVpc',
        region: 'us-east-1',
        state: 'OK',
        profile: 'test',
        time: now.toISOString(),
      },
    ])
  })

  it('should report OK if there are no internet gateways', async () => {
    mock('EC2', 'describeInternetGateways', {
      InternetGateways: [
        {
          InternetGatewayId: 'test',
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
        provider: 'aws',
        physicalId: 'test',
        service: 'ec2',
        rule: 'IgwAttachedToVpc',
        region: 'us-east-1',
        state: 'OK',
        profile: 'test',
        time: now.toISOString(),
      },
    ])
  })

  it('should report OK with no attachments via a scan', async () => {
    mock('EC2', 'describeInternetGateways', {
      InternetGateways: [
        {
          InternetGatewayId: 'test',
          Attachments: [],
        },
      ],
    })
    const audits = await handler({
      region: 'all',
    })

    expect(audits).to.eql([
      {
        provider: 'aws',
        physicalId: 'test',
        service: 'ec2',
        rule: 'IgwAttachedToVpc',
        region: 'us-east-1',
        state: 'OK',
        profile: undefined,
        time: now.toISOString(),
      },
    ])
  })

  it('should report nothing if there are no gateways', async () => {
    mock('EC2', 'describeInternetGateways', {})
    const audits = await handler({
      region: 'all',
    })
    expect(audits).to.eql([])
  })

  it('should report nothing if the domain is incorrect', async () => {
    mock('EC2', 'describeInternetGateways', {})
    const audits = await handler({
      region: 'all',
    })
    expect(audits).to.eql([])
  })

  it('should report nothing if there are no gateways but with a single pub region', async () => {
    mock('EC2', 'describeInternetGateways', {})
    const audits = await handler({
      region: 'us-east-1',
    })
    expect(audits).to.eql([])
  })
})
