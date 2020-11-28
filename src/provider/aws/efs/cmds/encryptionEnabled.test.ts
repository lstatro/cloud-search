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
    mock('EFS', 'describeFileSystems', {
      FileSystems: [{ Encrypted: true, FileSystemId: 'test' }],
    })
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
        rule: 'EncryptionEnabled',
        service: 'efs',
        state: 'OK',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })
  it('should return FAIL if encryption is NOT enabled', async () => {
    mock('EFS', 'describeFileSystems', {
      FileSystems: [{ Encrypted: false, FileSystemId: 'test' }],
    })
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
        rule: 'EncryptionEnabled',
        service: 'efs',
        state: 'FAIL',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })
})
