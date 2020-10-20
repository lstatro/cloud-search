import 'mocha'
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

  it('should return nothing if no trails are returned', async () => {
    mock('CloudTrail', 'listTrails', { Trails: [] })

    const audits = await handler({
      region: 'all',
    })

    expect(audits).to.eql([])
  })
})
