import { SinonFakeTimers, useFakeTimers } from 'sinon'
import { mock, restore } from 'aws-sdk-mock'

import { expect } from 'chai'
import { handler } from './encryptionEnabled'

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
  it('should return OK if encryption is enabled with default AWS key', async () => {
    mock('KMS', 'describeKey', {
      KeyMetadata: { Arn: 'test', KeyManager: 'AWS' },
    })
    mock('EFS', 'describeFileSystems', {
      FileSystems: [
        { Encrypted: true, FileSystemId: 'test', KmsKeyId: 'test' },
      ],
    })
    const audits = await handler({
      region: 'test',
      profile: 'test',
      resource: 'test',
      keyType: 'aws',
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
  it('should return OK if encryption is enabled with CMK', async () => {
    mock('KMS', 'describeKey', {
      KeyMetadata: { Arn: 'test', KeyManager: 'CUSTOMER' },
    })
    mock('EFS', 'describeFileSystems', {
      FileSystems: [
        { Encrypted: true, FileSystemId: 'test', KmsKeyId: 'test' },
      ],
    })
    const audits = await handler({
      region: 'test',
      profile: 'test',
      resource: 'test',
      keyType: 'cmk',
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
      resource: 'test',
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
