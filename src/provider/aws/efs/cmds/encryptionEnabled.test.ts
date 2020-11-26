import { mock, restore } from 'aws-sdk-mock'
import { useFakeTimers, SinonFakeTimers } from 'sinon'
import { handler } from './encryptionEnabled'
import { expect } from 'chai'

describe('efs encryption enabled', () => {
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
  it('should return no audits if no efs instances found', async () => {
    mock('EFS', 'describeFileSystems', { FileSystems: [] })
    const audits = await handler({
      region: 'test',
      profile: 'test',
    })
    expect(audits).to.eql([])
  })
  it('should return OK if encryption is enabled', async () => {
    mock('EFS', 'describeFileSystems', { FileSystems: [{ Encrypted: true }] })
    const audits = await handler({
      region: 'test',
      profile: 'test',
    })
    expect(audits).to.eql([])
  })
})
