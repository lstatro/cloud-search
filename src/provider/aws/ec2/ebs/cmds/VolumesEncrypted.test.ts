import 'mocha'
import { mock, restore } from 'aws-sdk-mock'
import { SinonFakeTimers, useFakeTimers } from 'sinon'
import { handler, VolumesEncryptedCliInterface } from './volumesEncrypted'
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
          Encrypted: true,
        },
      ],
    })
    const audits = await handler({
      region: 'all',
      profile: 'test',
      domain: 'pub',
      keyType: 'aws',
    } as VolumesEncryptedCliInterface)
    expect(audits[0].state).to.eql('OK')
  })

  it('should return FAIL for un-encrypted volumes', async () => {
    mock('KMS', 'describeKey', { KeyMetadata: { KeyManager: 'AWS' } })
    mock('EC2', 'describeVolumes', {
      Volumes: [
        {
          Encrypted: false,
        },
      ],
    })
    const audits = await handler({
      region: 'all',
      profile: 'test',
      domain: 'pub',
      keyType: 'aws',
    } as VolumesEncryptedCliInterface)
    expect(audits[0].state).to.eql('FAIL')
  })

  it('should return WARNING for encrypted volumes using the wrong key (type AWS)', async () => {
    mock('KMS', 'describeKey', { KeyMetadata: { KeyManager: 'AWS' } })
    mock('EC2', 'describeVolumes', {
      Volumes: [
        {
          Encrypted: true,
        },
      ],
    })
    const audits = await handler({
      region: 'all',
      profile: 'test',
      domain: 'pub',
      keyType: 'aws',
      keyArn: '_test',
    } as VolumesEncryptedCliInterface)
    expect(audits[0].state).to.eql('WARNING')
  })

  it('should return OK for encrypted volumes using the correct key (type AWS)', async () => {
    mock('KMS', 'describeKey', { KeyMetadata: { KeyManager: 'AWS' } })
    mock('EC2', 'describeVolumes', {
      Volumes: [
        {
          Encrypted: true,
          KmsKeyId: 'test',
        },
      ],
    })
    const audits = await handler({
      region: 'all',
      profile: 'test',
      domain: 'pub',
      keyType: 'aws',
      keyArn: 'test',
    } as VolumesEncryptedCliInterface)
    expect(audits[0].state).to.eql('OK')
  })

  it('should return WARNING for encrypted volumes using the wrong cmk key (type CMK)', async () => {
    mock('KMS', 'describeKey', { KeyMetadata: { KeyManager: 'AWS' } })
    mock('EC2', 'describeVolumes', {
      Volumes: [
        {
          Encrypted: true,
          KmsKeyId: 'test',
        },
      ],
    })
    const audits = await handler({
      region: 'all',
      profile: 'test',
      domain: 'pub',
      keyType: 'cmk',
      keyArn: '_test',
    } as VolumesEncryptedCliInterface)
    expect(audits[0].state).to.eql('WARNING')
  })

  it('should return FAIL for un-encrypted volumes using the wrong cmk key (type CMK)', async () => {
    mock('KMS', 'describeKey', { KeyMetadata: { KeyManager: 'AWS' } })
    mock('EC2', 'describeVolumes', {
      Volumes: [
        {
          Encrypted: false,
          KmsKeyId: 'test',
        },
      ],
    })
    const audits = await handler({
      region: 'all',
      profile: 'test',
      domain: 'pub',
      keyType: 'cmk',
      keyArn: '_test',
    } as VolumesEncryptedCliInterface)
    expect(audits[0].state).to.eql('FAIL')
  })

  it('should return OK for encrypted volumes using the wrong cmk key (type CMK)', async () => {
    mock('KMS', 'describeKey', { KeyMetadata: { KeyManager: 'AWS' } })
    mock('EC2', 'describeVolumes', {
      Volumes: [
        {
          Encrypted: true,
          KmsKeyId: 'test',
        },
      ],
    })
    const audits = await handler({
      region: 'all',
      profile: 'test',
      domain: 'pub',
      keyType: 'cmk',
      keyArn: 'test',
    } as VolumesEncryptedCliInterface)
    expect(audits[0].state).to.eql('OK')
  })

  it('should return WARNING for encrypted volumes with an unknown or undefined key (type CMK)', async () => {
    mock('KMS', 'describeKey', { KeyMetadata: { KeyManager: 'AWS' } })
    mock('EC2', 'describeVolumes', {
      Volumes: [
        {
          Encrypted: true,
        },
      ],
    })
    const audits = await handler({
      region: 'all',
      profile: 'test',
      domain: 'pub',
      keyType: 'cmk',
      keyArn: 'test',
    } as VolumesEncryptedCliInterface)
    expect(audits[0].state).to.eql('WARNING')
  })

  it('should return OK for encrypted volumes with a known cmk kms key', async () => {
    mock('KMS', 'describeKey', { KeyMetadata: { KeyManager: 'CUSTOMER' } })
    mock('EC2', 'describeVolumes', {
      Volumes: [
        {
          Encrypted: true,
          KmsKeyId: 'test',
        },
      ],
    })
    const audits = await handler({
      region: 'all',
      profile: 'test',
      domain: 'pub',
      keyType: 'cmk',
    } as VolumesEncryptedCliInterface)
    expect(audits[0].state).to.eql('OK')
  })

  it('should return OK for encrypted volumes with a resourceId', async () => {
    mock('KMS', 'describeKey', { KeyMetadata: { KeyManager: 'AWS' } })
    mock('EC2', 'describeVolumes', {
      Volumes: [
        {
          Encrypted: true,
          KmsKeyId: 'test',
        },
      ],
    })
    const audits = await handler({
      region: 'all',
      profile: 'test',
      domain: 'pub',
      keyType: 'aws',
      resourceId: 'test',
    } as VolumesEncryptedCliInterface)
    expect(audits[0].state).to.eql('OK')
  })

  it('should do nothing if there are no volumes', async () => {
    mock('KMS', 'describeKey', { KeyMetadata: { KeyManager: 'AWS' } })
    mock('EC2', 'describeVolumes', {})
    const audits = await handler({
      region: 'all',
      profile: 'test',
      domain: 'pub',
      keyType: 'aws',
      resourceId: 'test',
    } as VolumesEncryptedCliInterface)
    expect(audits).to.eql([])
  })

  it('it should default to us-east-1 in given region all and in pub cloud', async () => {
    mock('KMS', 'describeKey', { KeyMetadata: { KeyManager: 'AWS' } })
    mock('EC2', 'describeVolumes', {})
    const audits = await handler({
      region: 'all',
      profile: 'test',
      domain: 'pub',
      keyType: 'aws',
      resourceId: 'test',
    } as VolumesEncryptedCliInterface)
    expect(audits).to.eql([])
  })
})
