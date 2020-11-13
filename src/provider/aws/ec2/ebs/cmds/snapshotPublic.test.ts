import 'mocha'
import { useFakeTimers, SinonFakeTimers } from 'sinon'
import { mock, restore } from 'aws-sdk-mock'
import { handler } from './snapshotPublic'
import { expect } from 'chai'

describe('ebs snapshot should not be public', () => {
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

  it('should report nothing if no no snapshots are found', async () => {
    mock('EC2', 'describeSnapshots', {})

    let audits
    audits = await handler({
      profile: 'test',
      region: 'all',
    })

    expect(audits).to.eql([])

    audits = await handler({
      profile: 'test',
      region: 'all',
    })

    expect(audits).to.eql([])
  })

  it('should return OK for private snapshots', async () => {
    mock('EC2', 'describeSnapshotAttribute', { CreateVolumePermissions: [] })
    const audits = await handler({
      profile: 'test',
      region: 'test',
      resourceId: 'test',
    })

    expect(audits).to.eql([
      {
        physicalId: 'test',
        profile: 'test',
        provider: 'aws',
        region: 'test',
        rule: 'SnapshotPublic',
        service: 'ebs',
        state: 'OK',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })

  it('should return OK for private snapshots when doing a full scan', async () => {
    mock('EC2', 'describeSnapshots', { Snapshots: [{ SnapshotId: 'test' }] })
    mock('EC2', 'describeSnapshotAttribute', { CreateVolumePermissions: [] })
    const audits = await handler({
      profile: 'test',
      region: 'all',
    })

    expect(audits).to.eql([
      {
        physicalId: 'test',
        profile: 'test',
        provider: 'aws',
        region: 'us-east-1',
        rule: 'SnapshotPublic',
        service: 'ebs',
        state: 'OK',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })

  it('should return OK for private snapshots', async () => {
    mock('EC2', 'describeSnapshotAttribute', {})

    const audits = await handler({
      profile: 'test',
      region: 'test',
      resourceId: 'test',
    })

    expect(audits).to.eql([
      {
        physicalId: 'test',
        profile: 'test',
        provider: 'aws',
        region: 'test',
        rule: 'SnapshotPublic',
        service: 'ebs',
        state: 'OK',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })

  it('should return FAIL for public snapshots', async () => {
    mock('EC2', 'describeSnapshotAttribute', {
      CreateVolumePermissions: [{ Group: 'all' }],
    })

    const audits = await handler({
      profile: 'test',
      region: 'test',
      resourceId: 'test',
    })

    expect(audits).to.eql([
      {
        physicalId: 'test',
        profile: 'test',
        provider: 'aws',
        region: 'test',
        rule: 'SnapshotPublic',
        service: 'ebs',
        state: 'FAIL',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })

  it('should return OK for snapshots shared with specific accounts', async () => {
    mock('EC2', 'describeSnapshotAttribute', {
      CreateVolumePermissions: [{ UserId: 'test' }],
    })

    const audits = await handler({
      profile: 'test',
      region: 'test',
      resourceId: 'test',
    })

    expect(audits).to.eql([
      {
        physicalId: 'test',
        profile: 'test',
        provider: 'aws',
        region: 'test',
        rule: 'SnapshotPublic',
        service: 'ebs',
        state: 'OK',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })
})
