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

  it('should report FAIL', async () => {
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

  it('should report OK', async () => {
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

  it('should report OK', async () => {
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

  it('should report OK', async () => {
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

  it('should report OK', async () => {
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

  it('should report OK', async () => {
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

  it('should report UNKNOWN', async () => {
    mock('EC2', 'describeInternetGateways', Promise.reject('test'))
    const audits = await handler({
      region: 'all',
      domain: 'pub',
      resourceId: 'test',
    } as AWSScannerCliArgsInterface)

    expect(audits).to.eql([
      {
        provider: 'aws',
        physicalId: 'test',
        comment: 'unable to audit resource undefined - undefined',
        service: 'ec2',
        rule: 'IgwAttachedToVpc',
        region: 'all',
        state: 'UNKNOWN',
        profile: undefined,
        time: now.toISOString(),
      },
    ])
  })

  it('should report nothing', async () => {
    mock('EC2', 'describeInternetGateways', {})
    await handler({
      region: 'all',
      domain: 'pub',
    } as AWSScannerCliArgsInterface)
  })

  it('should report nothing', async () => {
    mock('EC2', 'describeInternetGateways', {})
    await handler({
      region: 'all',
      domain: 'gov',
    } as AWSScannerCliArgsInterface)
  })

  it('should report nothing', async () => {
    mock('EC2', 'describeInternetGateways', {})
    await handler({
      region: 'all',
      domain: 'test',
    } as AWSScannerCliArgsInterface)
  })

  it('should report nothing', async () => {
    mock('EC2', 'describeInternetGateways', {})
    await handler({
      region: 'us-east-1',
      domain: 'pub',
    } as AWSScannerCliArgsInterface)
  })

  it('should report nothing', async () => {
    mock('EC2', 'describeInternetGateways', {})
    await handler({
      region: 'us-gov-west-1',
      domain: 'gov',
    } as AWSScannerCliArgsInterface)
  })
})
