import { SinonFakeTimers, useFakeTimers } from 'sinon'
import { mock, restore } from 'aws-sdk-mock'

import { handler as detectorSourceCloudTrail } from './detectorSourceCloudTrail'
import { handler as detectorSourceDnsLogs } from './detectorSourceDnsLogs'
import { handler as detectorSourceFlowLogs } from './detectorSourceFlowLogs'
import { handler as detectorSourceS3Logs } from './detectorSourceS3Logs'
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
    mock('GuardDuty', 'getDetector', {})

    let audits

    audits = await detectorSourceCloudTrail({
      region: 'test',
      profile: 'test',
      source: 'CloudTrail',
      rule: 'test',
    })

    expect(audits).to.eql([])

    audits = await detectorSourceDnsLogs({
      region: 'test',
      profile: 'test',
      source: 'DNSLogs',
      rule: 'test',
    })

    expect(audits).to.eql([])

    audits = await detectorSourceFlowLogs({
      region: 'test',
      profile: 'test',
      source: 'FlowLogs',
      rule: 'test',
    })

    expect(audits).to.eql([])

    audits = await detectorSourceS3Logs({
      region: 'test',
      profile: 'test',
      source: 'S3Logs',
      rule: 'test',
    })

    expect(audits).to.eql([])
  })

  it('should report nothing if no detectors are reported', async () => {
    mock('GuardDuty', 'listDetectors', { DetectorIds: [] })
    mock('GuardDuty', 'getDetector', {})

    let audits

    audits = await detectorSourceCloudTrail({
      region: 'test',
      profile: 'test',
      source: 'CloudTrail',
      rule: 'test',
    })

    expect(audits).to.eql([])

    audits = await detectorSourceDnsLogs({
      region: 'test',
      profile: 'test',
      source: 'DNSLogs',
      rule: 'test',
    })

    expect(audits).to.eql([])

    audits = await detectorSourceFlowLogs({
      region: 'test',
      profile: 'test',
      source: 'FlowLogs',
      rule: 'test',
    })

    expect(audits).to.eql([])

    audits = await detectorSourceS3Logs({
      region: 'test',
      profile: 'test',
      source: 'S3Logs',
      rule: 'test',
    })

    expect(audits).to.eql([])
  })

  it('should report OK for each detector if their status is enabled', async () => {
    mock('GuardDuty', 'listDetectors', { DetectorIds: ['test'] })
    mock('GuardDuty', 'getDetector', {
      DataSources: {
        CloudTrail: { Status: 'ENABLED' },
        DNSLogs: { Status: 'ENABLED' },
        FlowLogs: { Status: 'ENABLED' },
        S3Logs: { Status: 'ENABLED' },
      },
    })

    let audits

    audits = await detectorSourceCloudTrail({
      region: 'test',
      profile: 'test',
      source: 'CloudTrail',
      rule: 'test',
    })

    expect(audits).to.eql([
      {
        physicalId: 'test',
        profile: 'test',
        provider: 'aws',
        region: 'test',
        rule: 'CloudTrailSourceEnable',
        service: 'guardduty',
        state: 'OK',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])

    audits = await detectorSourceDnsLogs({
      region: 'test',
      profile: 'test',
      source: 'DNSLogs',
      rule: 'test',
    })

    expect(audits).to.eql([
      {
        physicalId: 'test',
        profile: 'test',
        provider: 'aws',
        region: 'test',
        rule: 'DNSLogsSourceEnable',
        service: 'guardduty',
        state: 'OK',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])

    audits = await detectorSourceFlowLogs({
      region: 'test',
      profile: 'test',
      source: 'FlowLogs',
      rule: 'test',
    })

    expect(audits).to.eql([
      {
        physicalId: 'test',
        profile: 'test',
        provider: 'aws',
        region: 'test',
        rule: 'FlowLogsSourceEnable',
        service: 'guardduty',
        state: 'OK',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])

    audits = await detectorSourceS3Logs({
      region: 'test',
      profile: 'test',
      source: 'S3Logs',
      rule: 'test',
    })

    expect(audits).to.eql([
      {
        physicalId: 'test',
        profile: 'test',
        provider: 'aws',
        region: 'test',
        rule: 'S3LogsSourceEnable',
        service: 'guardduty',
        state: 'OK',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })

  it('should report FAIL for each detector if no data sources are found', async () => {
    mock('GuardDuty', 'listDetectors', { DetectorIds: ['test'] })
    mock('GuardDuty', 'getDetector', {})

    let audits

    audits = await detectorSourceCloudTrail({
      region: 'test',
      profile: 'test',
      source: 'CloudTrail',
      rule: 'test',
    })

    expect(audits).to.eql([
      {
        physicalId: 'test',
        profile: 'test',
        provider: 'aws',
        region: 'test',
        rule: 'CloudTrailSourceEnable',
        service: 'guardduty',
        state: 'FAIL',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])

    audits = await detectorSourceDnsLogs({
      region: 'test',
      profile: 'test',
      source: 'DNSLogs',
      rule: 'test',
    })

    expect(audits).to.eql([
      {
        physicalId: 'test',
        profile: 'test',
        provider: 'aws',
        region: 'test',
        rule: 'DNSLogsSourceEnable',
        service: 'guardduty',
        state: 'FAIL',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])

    audits = await detectorSourceFlowLogs({
      region: 'test',
      profile: 'test',
      source: 'FlowLogs',
      rule: 'test',
    })

    expect(audits).to.eql([
      {
        physicalId: 'test',
        profile: 'test',
        provider: 'aws',
        region: 'test',
        rule: 'FlowLogsSourceEnable',
        service: 'guardduty',
        state: 'FAIL',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])

    audits = await detectorSourceS3Logs({
      region: 'test',
      profile: 'test',
      source: 'S3Logs',
      rule: 'test',
    })

    expect(audits).to.eql([
      {
        physicalId: 'test',
        profile: 'test',
        provider: 'aws',
        region: 'test',
        rule: 'S3LogsSourceEnable',
        service: 'guardduty',
        state: 'FAIL',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })

  it('should report FAIL for each detector if if the detector status is disabled', async () => {
    mock('GuardDuty', 'listDetectors', { DetectorIds: ['test'] })
    mock('GuardDuty', 'getDetector', {
      DataSources: {
        CloudTrail: { Status: 'DISABLED' },
        DNSLogs: { Status: 'DISABLED' },
        FlowLogs: { Status: 'DISABLED' },
        S3Logs: { Status: 'DISABLED' },
      },
    })

    let audits

    audits = await detectorSourceCloudTrail({
      region: 'test',
      profile: 'test',
      resource: 'test',
      source: 'CloudTrail',
      rule: 'test',
    })

    expect(audits).to.eql([
      {
        physicalId: 'test',
        profile: 'test',
        provider: 'aws',
        region: 'test',
        rule: 'CloudTrailSourceEnable',
        service: 'guardduty',
        state: 'FAIL',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])

    audits = await detectorSourceDnsLogs({
      region: 'test',
      profile: 'test',
      resource: 'test',
      source: 'DNSLogs',
      rule: 'test',
    })

    expect(audits).to.eql([
      {
        physicalId: 'test',
        profile: 'test',
        provider: 'aws',
        region: 'test',
        rule: 'DNSLogsSourceEnable',
        service: 'guardduty',
        state: 'FAIL',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])

    audits = await detectorSourceFlowLogs({
      region: 'test',
      profile: 'test',
      resource: 'test',
      source: 'FlowLogs',
      rule: 'test',
    })

    expect(audits).to.eql([
      {
        physicalId: 'test',
        profile: 'test',
        provider: 'aws',
        region: 'test',
        rule: 'FlowLogsSourceEnable',
        service: 'guardduty',
        state: 'FAIL',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])

    audits = await detectorSourceS3Logs({
      region: 'test',
      profile: 'test',
      resource: 'test',
      source: 'S3Logs',
      rule: 'test',
    })

    expect(audits).to.eql([
      {
        physicalId: 'test',
        profile: 'test',
        provider: 'aws',
        region: 'test',
        rule: 'S3LogsSourceEnable',
        service: 'guardduty',
        state: 'FAIL',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })

  it('should report OK for some and FAIL for others depending on the detector state', async () => {
    mock('GuardDuty', 'listDetectors', { DetectorIds: ['test'] })
    mock('GuardDuty', 'getDetector', {
      DataSources: {
        CloudTrail: { Status: 'ENABLED' },
        DNSLogs: { Status: 'DISABLED' },
        FlowLogs: { Status: 'ENABLED' },
        S3Logs: { Status: 'DISABLED' },
      },
    })

    let audits

    audits = await detectorSourceCloudTrail({
      region: 'test',
      profile: 'test',
      resource: 'test',
      source: 'CloudTrail',
      rule: 'test',
    })

    expect(audits).to.eql([
      {
        physicalId: 'test',
        profile: 'test',
        provider: 'aws',
        region: 'test',
        rule: 'CloudTrailSourceEnable',
        service: 'guardduty',
        state: 'OK',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])

    audits = await detectorSourceDnsLogs({
      region: 'test',
      profile: 'test',
      resource: 'test',
      source: 'DNSLogs',
      rule: 'test',
    })

    expect(audits).to.eql([
      {
        physicalId: 'test',
        profile: 'test',
        provider: 'aws',
        region: 'test',
        rule: 'DNSLogsSourceEnable',
        service: 'guardduty',
        state: 'FAIL',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])

    audits = await detectorSourceFlowLogs({
      region: 'test',
      profile: 'test',
      resource: 'test',
      source: 'FlowLogs',
      rule: 'test',
    })

    expect(audits).to.eql([
      {
        physicalId: 'test',
        profile: 'test',
        provider: 'aws',
        region: 'test',
        rule: 'FlowLogsSourceEnable',
        service: 'guardduty',
        state: 'OK',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])

    audits = await detectorSourceS3Logs({
      region: 'test',
      profile: 'test',
      resource: 'test',
      source: 'S3Logs',
      rule: 'test',
    })

    expect(audits).to.eql([
      {
        physicalId: 'test',
        profile: 'test',
        provider: 'aws',
        region: 'test',
        rule: 'S3LogsSourceEnable',
        service: 'guardduty',
        state: 'FAIL',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })
})
