import 'mocha'
import 'chai'
import { useFakeTimers, SinonFakeTimers } from 'sinon'
import { mock, restore } from 'aws-sdk-mock'
import { handler } from './igwAttached'
import { AWSScannerCliArgsInterface } from 'cloud-search'
import { expect } from 'chai'

/** none of these tests should throw */

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

  it('should report FAIL if the gateway is attched', async () => {
    mock('EC2', 'describeInternetGateways', {
      InternetGateways: [
        {
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
      domain: 'pub',
    } as AWSScannerCliArgsInterface)
    expect(audits).to.eql([
      {
        name: undefined,
        provider: 'aws',
        physicalId: undefined,
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
      domain: 'pub',
    } as AWSScannerCliArgsInterface)

    expect(audits).to.eql([
      {
        name: undefined,
        provider: 'aws',
        physicalId: undefined,
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
          Attachments: [{}],
        },
      ],
    })
    const audits = await handler({
      region: 'us-east-1',
      profile: 'test',
      resourceId: 'test',
      domain: 'pub',
    } as AWSScannerCliArgsInterface)

    expect(audits).to.eql([
      {
        name: undefined,
        provider: 'aws',
        physicalId: undefined,
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
          Attachments: [],
        },
      ],
    })
    const audits = await handler({
      region: 'us-east-1',
      profile: 'test',
      resourceId: 'test',
      domain: 'pub',
    } as AWSScannerCliArgsInterface)

    expect(audits).to.eql([
      {
        name: undefined,
        provider: 'aws',
        physicalId: undefined,
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
      InternetGateways: [{}],
    })
    const audits = await handler({
      region: 'us-east-1',
      profile: 'test',
      resourceId: 'test',
      domain: 'pub',
    } as AWSScannerCliArgsInterface)

    expect(audits).to.eql([
      {
        name: undefined,
        provider: 'aws',
        physicalId: undefined,
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
          Attachments: [],
        },
      ],
    })
    const audits = await handler({
      region: 'all',
      domain: 'pub',
    } as AWSScannerCliArgsInterface)

    expect(audits).to.eql([
      {
        name: undefined,
        provider: 'aws',
        physicalId: undefined,
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
      domain: 'pub',
    } as AWSScannerCliArgsInterface)
    expect(audits).to.eql([])
  })

  it('should report nothing if there are not gateways in gov cloud', async () => {
    mock('EC2', 'describeInternetGateways', {})
    const audits = await handler({
      region: 'all',
      domain: 'gov',
    } as AWSScannerCliArgsInterface)
    expect(audits).to.eql([])
  })

  it('should report nothing if the domain is incorrect', async () => {
    mock('EC2', 'describeInternetGateways', {})
    const audits = await handler({
      region: 'all',
      domain: 'test',
    } as AWSScannerCliArgsInterface)
    expect(audits).to.eql([])
  })

  it('should report nothing if there are no gateways but with a single pub region', async () => {
    mock('EC2', 'describeInternetGateways', {})
    const audits = await handler({
      region: 'us-east-1',
      domain: 'pub',
    } as AWSScannerCliArgsInterface)
    expect(audits).to.eql([])
  })

  it('should report nothing if there are no gateways but in a single gov region', async () => {
    mock('EC2', 'describeInternetGateways', {})
    const audits = await handler({
      region: 'us-gov-west-1',
      domain: 'gov',
    } as AWSScannerCliArgsInterface)
    expect(audits).to.eql([])
  })
})
