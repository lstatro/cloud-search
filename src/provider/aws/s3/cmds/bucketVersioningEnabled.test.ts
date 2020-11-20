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
  it('should list all buckets in an account, and audit each', async () => {
    mock('EC2', 'listBuckets', [{ Name: 'test' }])
    const audits = await handler({
      region: 'test',
      profile: 'test',
      resourceId: 'test',
    })
    expect(audits).to.eql({})
  })
})
