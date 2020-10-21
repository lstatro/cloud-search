import 'mocha'
import { useFakeTimers, SinonFakeTimers } from 'sinon'
import { mock, restore } from 'aws-sdk-mock'
import { handler } from './snapshotEncrypted'
import { expect } from 'chai'

/** test2 */

describe('ebs snapshots should be encrypted', () => {
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

  it('should report OK for aws managed key type encrypted snapshots', async () => {
    mock('EC2', 'describeSnapshots', {
      Snapshots: [{ SnapshotId: 'test', KmsKeyId: 'test', Encrypted: true }],
    })
    mock('KMS', 'describeKey', { KeyMetadata: { KeyManager: 'AWS' } })

    const audits = await handler({
      profile: 'test',
      region: 'all',
      keyType: 'aws',
    })

    expect(audits).to.eql([
      {
        physicalId: 'test',
        profile: 'test',
        provider: 'aws',
        region: 'us-east-1',
        rule: 'SnapshotEncrypted',
        service: 'ebs',
        state: 'OK',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })

  it('should report FAIL un-encrypted snapshots', async () => {
    mock('EC2', 'describeSnapshots', {
      Snapshots: [{ SnapshotId: 'test' }],
    })
    mock('KMS', 'describeKey', { KeyMetadata: { KeyManager: 'AWS' } })

    const audits = await handler({
      profile: 'test',
      region: 'all',
      keyType: 'aws',
    })

    expect(audits).to.eql([
      {
        physicalId: 'test',
        profile: 'test',
        provider: 'aws',
        region: 'us-east-1',
        rule: 'SnapshotEncrypted',
        service: 'ebs',
        state: 'FAIL',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })

  it('should report WARNING for aws key managed encryption when looking for type cmk', async () => {
    mock('EC2', 'describeSnapshots', {
      Snapshots: [{ SnapshotId: 'test', KmsKeyId: 'test', Encrypted: true }],
    })
    mock('KMS', 'describeKey', { KeyMetadata: { KeyManager: 'AWS' } })

    const audits = await handler({
      profile: 'test',
      region: 'us-east-1',
      resourceId: 'test',
      keyType: 'cmk',
    })

    expect(audits).to.eql([
      {
        physicalId: 'test',
        profile: 'test',
        provider: 'aws',
        region: 'us-east-1',
        rule: 'SnapshotEncrypted',
        service: 'ebs',
        state: 'WARNING',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })

  it('should report OK for cmk key managed encryption when looking for type aws', async () => {
    mock('EC2', 'describeSnapshots', {
      Snapshots: [{ SnapshotId: 'test', KmsKeyId: 'test', Encrypted: true }],
    })
    mock('KMS', 'describeKey', { KeyMetadata: { KeyManager: 'CUSTOMER' } })

    const audits = await handler({
      profile: 'test',
      region: 'all',
      keyType: 'aws',
    })

    expect(audits).to.eql([
      {
        physicalId: 'test',
        profile: 'test',
        provider: 'aws',
        region: 'us-east-1',
        rule: 'SnapshotEncrypted',
        service: 'ebs',
        state: 'OK',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })
})
