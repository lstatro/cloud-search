import { mock, restore } from 'aws-sdk-mock'
import { SinonFakeTimers, useFakeTimers } from 'sinon'
import { handler } from './volumeEncrypted'
import { expect } from 'chai'

describe('ebs volume encryption', () => {
  const now = new Date(0)
  let clock: SinonFakeTimers
  beforeEach(() => {
    clock = useFakeTimers(now)
    mock('EC2', 'describeRegions', { Regions: [{ RegionName: 'us-east-1' }] })
    mock('KMS', 'listKeys', { Keys: [{ KeyId: 'test', KeyArn: 'test' }] })
  })

  afterEach(() => {
    clock.restore()
    restore()
  })

  it('should return OK for AWS key encrypted volumes', async () => {
    mock('KMS', 'describeKey', { KeyMetadata: { KeyManager: 'AWS' } })
    mock('EC2', 'describeVolumes', {
      Volumes: [
        {
          VolumeId: 'test',
          Encrypted: true,
          KmsKeyId: 'test',
        },
      ],
    })
    const audits = await handler({
      region: 'test',
      profile: 'test',
      keyType: 'aws',
    })
    expect(audits).to.eql([
      {
        provider: 'aws',
        physicalId: 'test',
        service: 'ebs',
        rule: 'VolumeEncrypted',
        region: 'test',
        state: 'OK',
        profile: 'test',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })

  it('should return FAIL for un-encrypted volumes', async () => {
    mock('KMS', 'describeKey', { KeyMetadata: { KeyManager: 'AWS' } })
    mock('EC2', 'describeVolumes', {
      Volumes: [
        {
          VolumeId: 'test',
          Encrypted: false,
        },
      ],
    })
    const audits = await handler({
      region: 'all',
      profile: 'test',
      keyType: 'aws',
    })
    expect(audits).to.eql([
      {
        provider: 'aws',
        physicalId: 'test',
        service: 'ebs',
        rule: 'VolumeEncrypted',
        region: 'us-east-1',
        state: 'FAIL',
        profile: 'test',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })

  it('should return OK for aws key encrypted volumes using the aws key type', async () => {
    mock('KMS', 'describeKey', { KeyMetadata: { KeyManager: 'AWS' } })
    mock('EC2', 'describeVolumes', {
      Volumes: [
        {
          VolumeId: 'test',
          Encrypted: true,
          KmsKeyId: 'test',
        },
      ],
    })

    const audits = await handler({
      region: 'test',
      profile: 'test',
      keyType: 'aws',
    })

    expect(audits).to.eql([
      {
        provider: 'aws',
        physicalId: 'test',
        service: 'ebs',
        rule: 'VolumeEncrypted',
        region: 'test',
        state: 'OK',
        profile: 'test',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })

  it('should return WARNING for aws key encrypted volumes using the cmk key type', async () => {
    mock('KMS', 'describeKey', { KeyMetadata: { KeyManager: 'AWS' } })
    mock('EC2', 'describeVolumes', {
      Volumes: [
        {
          VolumeId: 'test',
          Encrypted: true,
          KmsKeyId: 'test',
        },
      ],
    })

    const audits = await handler({
      region: 'test',
      profile: 'test',
      keyType: 'cmk',
    })

    expect(audits).to.eql([
      {
        provider: 'aws',
        physicalId: 'test',
        service: 'ebs',
        rule: 'VolumeEncrypted',
        region: 'test',
        state: 'WARNING',
        profile: 'test',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })

  it('should do nothing if there are no volumes', async () => {
    mock('KMS', 'describeKey', { KeyMetadata: { KeyManager: 'AWS' } })
    mock('EC2', 'describeVolumes', {})
    const audits = await handler({
      region: 'test',
      profile: 'test',
      keyType: 'aws',
      resourceId: 'test',
    })
    expect(audits).to.eql([])
  })

  it('it should default to us-east-1 in given region all and in pub cloud', async () => {
    mock('KMS', 'describeKey', { KeyMetadata: { KeyManager: 'AWS' } })
    mock('EC2', 'describeVolumes', {})
    const audits = await handler({
      region: 'us-east-1',
      profile: 'test',
      keyType: 'aws',
      resourceId: 'test',
    })
    expect(audits).to.eql([])
  })
})
