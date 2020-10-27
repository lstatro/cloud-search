import 'mocha'
import { mock, restore } from 'aws-sdk-mock'
import { useFakeTimers, SinonFakeTimers } from 'sinon'
import { handler } from './detectorExists'
import { expect } from 'chai'

describe('guardduty detectors should exist in a region', () => {
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

  it('should report nothing if no detectors are found', async () => {
    mock('GuardDuty', 'listDetectors', {})

    const audits = await handler({
      region: 'all',
      profile: 'test',
    })
    expect(audits).to.eql([
      {
        physicalId: 'us-east-1',
        profile: 'test',
        provider: 'aws',
        region: 'us-east-1',
        rule: 'DetectorExists',
        service: 'guardduty',
        state: 'FAIL',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })

  it('should report nothing if no detectors are reported', async () => {
    mock('GuardDuty', 'listDetectors', { DetectorIds: [] })

    const audits = await handler({
      region: 'all',
      profile: 'test',
    })
    expect(audits).to.eql([
      {
        physicalId: 'us-east-1',
        profile: 'test',
        provider: 'aws',
        region: 'us-east-1',
        rule: 'DetectorExists',
        service: 'guardduty',
        state: 'FAIL',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })

  it('should report OK a detector exists in the target region', async () => {
    mock('GuardDuty', 'listDetectors', { DetectorIds: ['test'] })

    const audits = await handler({
      region: 'us-east-1',
      profile: 'test',
    })
    expect(audits).to.eql([
      {
        physicalId: 'us-east-1',
        profile: 'test',
        provider: 'aws',
        region: 'us-east-1',
        rule: 'DetectorExists',
        service: 'guardduty',
        state: 'OK',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })

  it('should report FAIL if no detectors exist in the target region', async () => {
    mock('GuardDuty', 'listDetectors', { DetectorIds: [] })

    const audits = await handler({
      region: 'us-east-1',
      profile: 'test',
    })
    expect(audits).to.eql([
      {
        physicalId: 'us-east-1',
        profile: 'test',
        provider: 'aws',
        region: 'us-east-1',
        rule: 'DetectorExists',
        service: 'guardduty',
        state: 'FAIL',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })

  it('should report WARNING if more then one detector exists in the target region', async () => {
    mock('GuardDuty', 'listDetectors', { DetectorIds: ['test1', 'test2'] })

    const audits = await handler({
      region: 'us-east-1',
      profile: 'test',
    })
    expect(audits).to.eql([
      {
        physicalId: 'us-east-1',
        profile: 'test',
        provider: 'aws',
        region: 'us-east-1',
        rule: 'DetectorExists',
        service: 'guardduty',
        state: 'WARNING',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })
})
