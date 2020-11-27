import 'mocha'
import { useFakeTimers, SinonFakeTimers } from 'sinon'
import { mock, restore } from 'aws-sdk-mock'
import { handler } from './bucketVersioningEnabled'
import { expect } from 'chai'

describe('S3 Bucket Versioning Enabled', () => {
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
  it('should return empty audit if no buckets found', async () => {
    mock('S3', 'listBuckets', {
      Buckets: [],
    })
    const audits = await handler({
      region: 'test',
      profile: 'test',
    })
    expect(audits).to.eql([])
  })

  it('should return OK if versioning is enabled', async () => {
    mock('S3', 'listBuckets', {
      Buckets: [
        {
          Name: 'test',
        },
      ],
    })
    mock('S3', 'getBucketVersioning', { Status: 'Enabled' })
    const audits = await handler({
      region: 'test',
      profile: 'test',
    })
    expect(audits).to.eql([
      {
        physicalId: 'test',
        profile: 'test',
        provider: 'aws',
        region: 'test',
        rule: 'BucketVersioningEnabled',
        service: 's3',
        state: 'OK',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })
  it('should return FAIL if versioning is suspended', async () => {
    mock('S3', 'listBuckets', {
      Buckets: [
        {
          Name: 'test',
        },
      ],
    })
    mock('S3', 'getBucketVersioning', { Status: 'Suspended' })
    const audits = await handler({
      region: 'test',
      profile: 'test',
    })
    expect(audits).to.eql([
      {
        physicalId: 'test',
        profile: 'test',
        provider: 'aws',
        region: 'test',
        rule: 'BucketVersioningEnabled',
        service: 's3',
        state: 'FAIL',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })
  it('should return OK when a resourceId is passed in and versioning is enabled', async () => {
    mock('S3', 'getBucketVersioning', { Status: 'Enabled' })
    const audits = await handler({
      region: 'test',
      profile: 'test',
      resourceId: 'test',
    })
    expect(audits).to.eql([
      {
        physicalId: 'test',
        profile: 'test',
        provider: 'aws',
        region: 'test',
        rule: 'BucketVersioningEnabled',
        service: 's3',
        state: 'OK',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })
  it('should return UNKNOWN when a fault is caught in the audit function', async () => {
    const audits = await handler({
      region: 'test',
      profile: 'test',
      resourceId: 'test',
    })
    expect(audits).to.eql([
      {
        physicalId: 'test',
        profile: 'test',
        provider: 'aws',
        region: 'test',
        rule: 'BucketVersioningEnabled',
        service: 's3',
        state: 'UNKNOWN',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })
})
