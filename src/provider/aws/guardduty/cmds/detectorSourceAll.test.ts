import 'mocha'
import { mock, restore } from 'aws-sdk-mock'
import { useFakeTimers, SinonFakeTimers } from 'sinon'
import { handler as detectorSourceCloudTrail } from './detectorSourceCloudTrail'
import { handler as detectorSourceDnsLogs } from './detectorSourceDnsLogs'
import { handler as detectorSourceFlowLogs } from './detectorSourceFlowLogs'
import { handler as detectorSourceS3Logs } from './detectorSourceS3Logs'
// import { expect } from 'chai'

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

  const handlers = [
    detectorSourceCloudTrail,
    detectorSourceDnsLogs,
    detectorSourceFlowLogs,
    detectorSourceS3Logs,
  ]

  for (const handler of handlers) {
    it('should report nothing if no detectors are reported', async () => {
      mock('GuardDuty', 'listDetectors', { DetectorIds: [] })
      mock('GuardDuty', 'getDetector', {})

      await handler({
        region: 'test',
        profile: 'test',
        source: 'test' as 'CloudTrail',
        rule: 'test',
      })
    })

    it('should report nothing if no detectors are found', async () => {
      mock('GuardDuty', 'listDetectors', {})
      mock('GuardDuty', 'getDetector', {})

      await handler({
        region: 'test',
        profile: 'test',
        source: 'test' as 'CloudTrail',
        rule: 'test',
      })
    })

    it('should report OK if no detectors are found', async () => {
      mock('GuardDuty', 'listDetectors', {})
      mock('GuardDuty', 'getDetector', {})

      await handler({
        region: 'test',
        profile: 'test',
        source: 'test' as 'CloudTrail',
        rule: 'test',
      })
    })
  }
})
