import { mock, restore } from 'aws-sdk-mock'
import { useFakeTimers, SinonFakeTimers } from 'sinon'
import { handler } from './detectorEnabled'
import { expect } from 'chai'

describe('existing guardduty detectors should be enabled', () => {
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
    expect(audits).to.eql([])
  })

  it('should report nothing if no detectors are reported', async () => {
    mock('GuardDuty', 'listDetectors', { DetectorIds: [] })

    const audits = await handler({
      region: 'all',
      profile: 'test',
    })
    expect(audits).to.eql([])
  })

  it('should report OK if the detector is enabled', async () => {
    mock('GuardDuty', 'listDetectors', { DetectorIds: ['test'] })

    mock('GuardDuty', 'getDetector', { Status: 'ENABLED' })

    const audits = await handler({
      region: 'all',
      profile: 'test',
    })
    expect(audits).to.eql([
      {
        physicalId: 'test',
        profile: 'test',
        provider: 'aws',
        region: 'us-east-1',
        rule: 'DetectorEnabled',
        service: 'guardduty',
        state: 'OK',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })

  it('should report OK if the detector is not enabled', async () => {
    mock('GuardDuty', 'listDetectors', { DetectorIds: ['test'] })

    mock('GuardDuty', 'getDetector', { Status: 'DISABLED' })

    const audits = await handler({
      region: 'all',
      profile: 'test',
    })
    expect(audits).to.eql([
      {
        physicalId: 'test',
        profile: 'test',
        provider: 'aws',
        region: 'us-east-1',
        rule: 'DetectorEnabled',
        service: 'guardduty',
        state: 'FAIL',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })

  it('should report UNKNOWN if the detector is an unexpected state', async () => {
    mock('GuardDuty', 'listDetectors', { DetectorIds: ['test'] })

    mock('GuardDuty', 'getDetector', { Status: 'test' })

    const audits = await handler({
      region: 'us-east-1',
      profile: 'test',
    })
    expect(audits).to.eql([
      {
        physicalId: 'test',
        profile: 'test',
        provider: 'aws',
        region: 'us-east-1',
        rule: 'DetectorEnabled',
        service: 'guardduty',
        state: 'UNKNOWN',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })
})
