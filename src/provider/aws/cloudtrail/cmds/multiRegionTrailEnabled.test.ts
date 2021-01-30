import { SinonFakeTimers, useFakeTimers } from 'sinon'
import { mock, restore } from 'aws-sdk-mock'

import { expect } from 'chai'
import { handler } from './multiRegionTrailEnabled'

describe('cloudtrail multi region trail enabled', () => {
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

  it('should return nothing if no trails are found', async () => {
    mock('CloudTrail', 'listTrails', {})

    const audits = await handler({
      region: 'all',
    })

    expect(audits).to.eql([])
  })

  it('should return nothing if no trails are returned', async () => {
    mock('CloudTrail', 'listTrails', { Trails: [] })

    const audits = await handler({
      region: 'all',
    })

    expect(audits).to.eql([])
  })

  it('should return OK if a trail is multi-region enabled and logging on a scan', async () => {
    mock('CloudTrail', 'listTrails', {
      Trails: [
        {
          TrailARN: 'test',
          HomeRegion: 'us-east-1',
        },
      ],
    })

    mock('CloudTrail', 'getTrail', {
      Trail: {
        IsMultiRegionTrail: true,
      },
    })

    mock('CloudTrail', 'getTrailStatus', {
      IsLogging: true,
    })

    const audits = await handler({
      region: 'us-east-1',
      profile: 'test',
    })

    expect(audits).to.eql([
      {
        physicalId: 'test',
        provider: 'aws',
        profile: 'test',
        region: 'us-east-1',
        rule: 'MultiRegionTrailEnabled',
        service: 'cloudtrail',
        state: 'OK',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })

  it('should return OK if a trail is multi-region enabled and logging on a single resource', async () => {
    mock('CloudTrail', 'listTrails', {
      Trails: [
        {
          TrailARN: 'test',
        },
      ],
    })

    mock('CloudTrail', 'getTrail', {
      Trail: {
        IsMultiRegionTrail: true,
      },
    })

    mock('CloudTrail', 'getTrailStatus', {
      IsLogging: true,
    })

    const audits = await handler({
      region: 'test',
      resource: 'test',
      profile: 'test',
    })

    expect(audits).to.eql([
      {
        physicalId: 'test',
        provider: 'aws',
        profile: 'test',
        region: 'test',
        rule: 'MultiRegionTrailEnabled',
        service: 'cloudtrail',
        state: 'OK',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })

  it('should return WARNING if a trail is multi-region enabled and not logging', async () => {
    mock('CloudTrail', 'listTrails', {
      Trails: [
        {
          TrailARN: 'test',
          HomeRegion: 'us-east-1',
        },
      ],
    })

    mock('CloudTrail', 'getTrail', {
      Trail: {
        IsMultiRegionTrail: true,
      },
    })

    mock('CloudTrail', 'getTrailStatus', {
      IsLogging: false,
    })

    const audits = await handler({
      region: 'all',
      profile: 'test',
    })

    expect(audits).to.eql([
      {
        physicalId: 'test',
        provider: 'aws',
        profile: 'test',
        region: 'us-east-1',
        rule: 'MultiRegionTrailEnabled',
        service: 'cloudtrail',
        state: 'WARNING',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })

  it('should return FAIL if a trail is multi-region is not enabled', async () => {
    mock('CloudTrail', 'listTrails', {
      Trails: [
        {
          TrailARN: 'test',
          HomeRegion: 'us-east-1',
        },
      ],
    })

    mock('CloudTrail', 'getTrail', {
      Trail: {
        IsMultiRegionTrail: false,
      },
    })

    mock('CloudTrail', 'getTrailStatus', {
      IsLogging: true,
    })

    const audits = await handler({
      region: 'all',
      profile: 'test',
    })

    expect(audits).to.eql([
      {
        physicalId: 'test',
        provider: 'aws',
        profile: 'test',
        region: 'us-east-1',
        rule: 'MultiRegionTrailEnabled',
        service: 'cloudtrail',
        state: 'FAIL',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })

  it('should return UNKNOWN if a trail arn is valid, but does not return trail metadata', async () => {
    mock('CloudTrail', 'listTrails', {
      Trails: [
        {
          TrailARN: 'test',
          HomeRegion: 'us-east-1',
        },
      ],
    })

    mock('CloudTrail', 'getTrail', {})

    mock('CloudTrail', 'getTrailStatus', {
      IsLogging: true,
    })

    const audits = await handler({
      region: 'us-east-1',
      profile: 'test',
    })

    expect(audits).to.eql([
      {
        physicalId: 'test',
        provider: 'aws',
        profile: 'test',
        region: 'us-east-1',
        rule: 'MultiRegionTrailEnabled',
        service: 'cloudtrail',
        state: 'UNKNOWN',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })

  it('should return nothing if a trail home region is not the target home region', async () => {
    mock('CloudTrail', 'listTrails', {
      Trails: [
        {
          TrailARN: 'test',
          HomeRegion: 'us-west-1',
        },
      ],
    })

    mock('CloudTrail', 'getTrail', {})

    mock('CloudTrail', 'getTrailStatus', {
      IsLogging: true,
    })

    const audits = await handler({
      region: 'us-east-1',
      profile: 'test',
    })

    expect(audits).to.eql([])
  })
})
