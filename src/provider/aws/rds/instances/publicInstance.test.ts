import 'mocha'
import { useFakeTimers, SinonFakeTimers } from 'sinon'
import { mock, restore } from 'aws-sdk-mock'
import { handler } from './publicInstance'
import { expect } from 'chai'
import { AWSScannerInterface } from 'cloud-search'

describe('rds public instance', () => {
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

  it('should report nothing if no rds instances are found', async () => {
    mock('RDS', 'describeDBInstances', {
      DBInstances: [],
    })

    let audits

    audits = await handler({
      region: 'all',
      profile: 'test',
    } as AWSScannerInterface)
    expect(audits).to.eql([])

    restore()

    mock('RDS', 'describeDBInstances', {})

    audits = await handler({
      region: 'all',
      profile: 'test',
    } as AWSScannerInterface)
    expect(audits).to.eql([])
  })

  it('should report nothing if no rds instances are reported', async () => {
    mock('RDS', 'describeDBInstances', {})

    const audits = await handler({
      region: 'all',
      profile: 'test',
    } as AWSScannerInterface)
    expect(audits).to.eql([])
  })

  it('should report OK if the instance is not public', async () => {
    mock('RDS', 'describeDBInstances', {
      DBInstances: [
        {
          DBInstanceArn: 'test',
          PubliclyAccessible: false,
        },
      ],
    })

    const audits = await handler({
      region: 'all',
      profile: 'test',
    } as AWSScannerInterface)
    expect(audits).to.eql([
      {
        physicalId: 'test',
        profile: 'test',
        provider: 'aws',
        region: 'us-east-1',
        rule: 'PublicInstance',
        service: 'rds',
        state: 'OK',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })

  it('should report FAIL if the instance is public', async () => {
    mock('RDS', 'describeDBInstances', {
      DBInstances: [
        {
          DBInstanceArn: 'test',
          PubliclyAccessible: true,
        },
      ],
    })

    const audits = await handler({
      region: 'us-east-1',
      resourceId: 'test',
      profile: 'test',
    } as AWSScannerInterface)
    expect(audits).to.eql([
      {
        physicalId: 'test',
        profile: 'test',
        provider: 'aws',
        region: 'us-east-1',
        rule: 'PublicInstance',
        service: 'rds',
        state: 'FAIL',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })

  it('should default to UNKNOWN if the instance state is unexpected', async () => {
    mock('RDS', 'describeDBInstances', {
      DBInstances: [
        {
          DBInstanceArn: 'test',
        },
      ],
    })

    const audits = await handler({
      region: 'us-east-1',
      resourceId: 'test',
      profile: 'test',
    } as AWSScannerInterface)
    expect(audits).to.eql([
      {
        physicalId: 'test',
        profile: 'test',
        provider: 'aws',
        region: 'us-east-1',
        rule: 'PublicInstance',
        service: 'rds',
        state: 'UNKNOWN',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })
})
