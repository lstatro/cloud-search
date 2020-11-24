import { useFakeTimers, SinonFakeTimers } from 'sinon'
import { mock, restore } from 'aws-sdk-mock'
import { handler } from './trailEvents'
import { expect } from 'chai'

describe('cloudtrail events must be configured correctly', () => {
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

  it('should return nothing if the trail is not in the targeted region', async () => {
    mock('CloudTrail', 'listTrails', {
      Trails: [
        {
          TrailARN: 'test',
          HomeRegion: 'test',
        },
      ],
    })

    const audits = await handler({
      region: 'us-east-2',
    })

    expect(audits).to.eql([])
  })

  it('should return OK if the trail is configured correctly', async () => {
    mock('CloudTrail', 'listTrails', {
      Trails: [
        {
          TrailARN: 'test',
          HomeRegion: 'us-east-1',
        },
      ],
    })

    mock('CloudTrail', 'getTrailStatus', {
      IsLogging: true,
    })

    mock('CloudTrail', 'getEventSelectors', {
      EventSelectors: [
        {
          ReadWriteType: 'All',
          IncludeManagementEvents: true,
          DataResources: [
            {
              Type: 'AWS::S3::Object',
              Values: ['arn:aws:s3'],
            },
            {
              Type: 'AWS::Lambda::Function',
              Values: ['arn:aws:lambda'],
            },
          ],
          ExcludeManagementEventSources: [],
        },
      ],
    })

    const audits = await handler({
      region: 'us-east-1',
      resourceId: 'test',
      profile: 'test',
    })

    expect(audits).to.eql([
      {
        physicalId: 'test',
        profile: 'test',
        provider: 'aws',
        region: 'us-east-1',
        rule: 'TrailEvents',
        service: 'cloudtrail',
        state: 'OK',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })

  it('should return WARNING if the trail is configured correctly, but not logging', async () => {
    mock('CloudTrail', 'listTrails', {
      Trails: [
        {
          TrailARN: 'test',
          HomeRegion: 'us-east-1',
        },
      ],
    })

    mock('CloudTrail', 'getTrailStatus', {
      IsLogging: false,
    })

    mock('CloudTrail', 'getEventSelectors', {
      EventSelectors: [
        {
          ReadWriteType: 'All',
          IncludeManagementEvents: true,
          DataResources: [
            {
              Type: 'AWS::S3::Object',
              Values: ['arn:aws:s3'],
            },
            {
              Type: 'AWS::Lambda::Function',
              Values: ['arn:aws:lambda'],
            },
          ],
          ExcludeManagementEventSources: [],
        },
      ],
    })

    const audits = await handler({
      region: 'us-east-1',
      resourceId: 'test',
      profile: 'test',
    })

    expect(audits).to.eql([
      {
        physicalId: 'test',
        profile: 'test',
        provider: 'aws',
        region: 'us-east-1',
        rule: 'TrailEvents',
        service: 'cloudtrail',
        state: 'WARNING',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })

  it('should return FAIL if the trail is not capturing any data events', async () => {
    mock('CloudTrail', 'listTrails', {
      Trails: [
        {
          TrailARN: 'test',
          HomeRegion: 'us-east-1',
        },
      ],
    })

    mock('CloudTrail', 'getTrailStatus', {
      IsLogging: false,
    })

    mock('CloudTrail', 'getEventSelectors', {
      EventSelectors: [
        {
          ReadWriteType: 'All',
          IncludeManagementEvents: true,
          DataResources: [],
          ExcludeManagementEventSources: [],
        },
      ],
    })

    const audits = await handler({
      region: 'us-east-1',
      resourceId: 'test',
      profile: 'test',
    })

    expect(audits).to.eql([
      {
        physicalId: 'test',
        profile: 'test',
        provider: 'aws',
        region: 'us-east-1',
        rule: 'TrailEvents',
        service: 'cloudtrail',
        state: 'FAIL',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })

  it('should return FAIL if the trail does not have any event selectors', async () => {
    mock('CloudTrail', 'listTrails', {
      Trails: [
        {
          TrailARN: 'test',
          HomeRegion: 'us-east-1',
        },
      ],
    })

    mock('CloudTrail', 'getTrailStatus', {
      IsLogging: false,
    })

    mock('CloudTrail', 'getEventSelectors', {})

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
        rule: 'TrailEvents',
        service: 'cloudtrail',
        state: 'FAIL',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })

  it('should return FAIL if the trail does not including management events', async () => {
    mock('CloudTrail', 'listTrails', {
      Trails: [
        {
          TrailARN: 'test',
          HomeRegion: 'us-east-1',
        },
      ],
    })

    mock('CloudTrail', 'getTrailStatus', {
      IsLogging: false,
    })

    mock('CloudTrail', 'getEventSelectors', {
      EventSelectors: [
        {
          ReadWriteType: 'All',
          IncludeManagementEvents: false,
          DataResources: [
            {
              Type: 'AWS::S3::Object',
              Values: ['arn:aws:s3'],
            },
            {
              Type: 'AWS::Lambda::Function',
              Values: ['arn:aws:lambda'],
            },
          ],
          ExcludeManagementEventSources: [],
        },
      ],
    })

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
        rule: 'TrailEvents',
        service: 'cloudtrail',
        state: 'FAIL',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })

  it('should return FAIL if the trail is not set to capture read and write events', async () => {
    mock('CloudTrail', 'listTrails', {
      Trails: [
        {
          TrailARN: 'test',
          HomeRegion: 'us-east-1',
        },
      ],
    })

    mock('CloudTrail', 'getTrailStatus', {
      IsLogging: false,
    })

    mock('CloudTrail', 'getEventSelectors', {
      EventSelectors: [
        {
          ReadWriteType: 'READ',
          IncludeManagementEvents: true,
          DataResources: [
            {
              Type: 'AWS::S3::Object',
              Values: ['arn:aws:s3'],
            },
            {
              Type: 'AWS::Lambda::Function',
              Values: ['arn:aws:lambda'],
            },
          ],
          ExcludeManagementEventSources: [],
        },
      ],
    })

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
        rule: 'TrailEvents',
        service: 'cloudtrail',
        state: 'FAIL',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })

  it('should return FAIL if the trail does not have a DataResources attribute', async () => {
    mock('CloudTrail', 'listTrails', {
      Trails: [
        {
          TrailARN: 'test',
          HomeRegion: 'us-east-1',
        },
      ],
    })

    mock('CloudTrail', 'getTrailStatus', {
      IsLogging: false,
    })

    mock('CloudTrail', 'getEventSelectors', {
      EventSelectors: [
        {
          ReadWriteType: 'READ',
          IncludeManagementEvents: true,
          ExcludeManagementEventSources: [],
        },
      ],
    })

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
        rule: 'TrailEvents',
        service: 'cloudtrail',
        state: 'FAIL',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })

  it('should return FAIL if the trails DataResources array does not have a values array', async () => {
    mock('CloudTrail', 'listTrails', {
      Trails: [
        {
          TrailARN: 'test',
          HomeRegion: 'us-east-1',
        },
      ],
    })

    mock('CloudTrail', 'getTrailStatus', {
      IsLogging: false,
    })

    mock('CloudTrail', 'getEventSelectors', {
      EventSelectors: [
        {
          ReadWriteType: 'READ',
          IncludeManagementEvents: true,
          DataResources: [
            {
              Type: 'AWS::S3::Object',
            },
            {
              Type: 'AWS::Lambda::Function',
              Values: ['arn:aws:lambda'],
            },
          ],
          ExcludeManagementEventSources: [],
        },
      ],
    })

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
        rule: 'TrailEvents',
        service: 'cloudtrail',
        state: 'FAIL',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })

  it('should return FAIL if the trails DataResources array does not have the exactly expected target value', async () => {
    mock('CloudTrail', 'listTrails', {
      Trails: [
        {
          TrailARN: 'test',
          HomeRegion: 'us-east-1',
        },
      ],
    })

    mock('CloudTrail', 'getTrailStatus', {
      IsLogging: false,
    })

    mock('CloudTrail', 'getEventSelectors', {
      EventSelectors: [
        {
          ReadWriteType: 'READ',
          IncludeManagementEvents: true,
          DataResources: [
            {
              Type: 'AWS::S3::Object',
              Values: ['test'],
            },
            {
              Type: 'AWS::Lambda::Function',
              Values: ['arn:aws:lambda'],
            },
          ],
          ExcludeManagementEventSources: [],
        },
      ],
    })

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
        rule: 'TrailEvents',
        service: 'cloudtrail',
        state: 'FAIL',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })
})
