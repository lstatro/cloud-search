import { useFakeTimers, SinonFakeTimers } from 'sinon'
import { mock, restore } from 'aws-sdk-mock'
import { handler } from './trailEncrypted'
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

  it('should return nothing if no trails are returned', async () => {
    mock('CloudTrail', 'listTrails', { Trails: [] })

    const audits = await handler({
      region: 'all',
    })

    expect(audits).to.eql([])
  })

  it('should return OK if the trail is encrypted', async () => {
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
        KmsKeyId: 'test',
      },
    })

    mock('KMS', 'describeKey', {
      KeyMetadata: { Arn: 'test', KeyManager: 'AWS' },
    })

    const audits = await handler({
      region: 'all',
      keyType: 'aws',
      profile: 'test',
    })

    expect(audits).to.eql([
      {
        physicalId: 'test',
        profile: 'test',
        provider: 'aws',
        region: 'us-east-1',
        rule: 'TrailEncrypted',
        service: 'cloudtrail',
        state: 'OK',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })

  it('should return UNKNOWN if there is no trail metadata', async () => {
    mock('CloudTrail', 'listTrails', {
      Trails: [
        {
          TrailARN: 'test',
          HomeRegion: 'us-east-1',
        },
      ],
    })

    mock('CloudTrail', 'getTrail', {})

    mock('KMS', 'describeKey', {
      KeyMetadata: { Arn: 'test', KeyManager: 'AWS' },
    })

    const audits = await handler({
      region: 'all',
      keyType: 'aws',
      profile: 'test',
    })

    expect(audits).to.eql([
      {
        physicalId: 'test',
        profile: 'test',
        provider: 'aws',
        region: 'us-east-1',
        rule: 'TrailEncrypted',
        service: 'cloudtrail',
        state: 'UNKNOWN',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })

  it('should return FAIL if there is no key in the metadata', async () => {
    mock('CloudTrail', 'listTrails', {
      Trails: [
        {
          TrailARN: 'test',
          HomeRegion: 'us-east-1',
        },
      ],
    })

    mock('CloudTrail', 'getTrail', {
      Trail: {},
    })

    mock('KMS', 'describeKey', {
      KeyMetadata: { Arn: 'test', KeyManager: 'AWS' },
    })

    const audits = await handler({
      region: 'all',
      keyType: 'aws',
      profile: 'test',
    })

    expect(audits).to.eql([
      {
        physicalId: 'test',
        profile: 'test',
        provider: 'aws',
        region: 'us-east-1',
        rule: 'TrailEncrypted',
        service: 'cloudtrail',
        state: 'FAIL',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })

  it('should return WARNING if there is a AWS managed key when looking for a cmk', async () => {
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
        KmsKeyId: 'test',
      },
    })

    mock('KMS', 'describeKey', {
      KeyMetadata: { Arn: 'test', KeyManager: 'AWS' },
    })

    const audits = await handler({
      region: 'us-east-1',
      resourceId: 'test',
      keyType: 'cmk',
      profile: 'test',
    })

    expect(audits).to.eql([
      {
        physicalId: 'test',
        profile: 'test',
        provider: 'aws',
        region: 'us-east-1',
        rule: 'TrailEncrypted',
        service: 'cloudtrail',
        state: 'WARNING',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })
})
