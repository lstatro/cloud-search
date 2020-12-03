import { mock, restore } from 'aws-sdk-mock'
import { SinonFakeTimers, useFakeTimers } from 'sinon'
import { expect } from 'chai'
import { handler } from './secretEncryptedWithCmk'

describe('secrets-manager secrets rotation should be enabled', () => {
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

  it('should report nothing is listSecrets returns an empty object', async () => {
    mock('SecretsManager', 'listSecrets', {})

    const audits = await handler({ region: 'test' })

    expect(audits).to.eql([])
  })

  it('should report nothing is listSecrets returns an object with an empty array of secrets', async () => {
    mock('SecretsManager', 'listSecrets', { SecretList: [] })

    const audits = await handler({ region: 'test' })

    expect(audits).to.eql([])
  })

  it('should report FAIL for secrets that use the default secrets manager encryption', async () => {
    mock('SecretsManager', 'listSecrets', {
      SecretList: [{ Name: 'test' }],
    })

    const audits = await handler({ region: 'test' })

    expect(audits).to.eql([
      {
        physicalId: 'test',
        provider: 'aws',
        profile: undefined,
        region: 'test',
        rule: 'SecretEncryptedWithCmk',
        service: 'secrets-manager',
        state: 'FAIL',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })

  it('should report OK for secrets that use CMKs for encryption', async () => {
    mock('SecretsManager', 'listSecrets', {
      SecretList: [{ Name: 'test', KmsKeyId: 'test' }],
    })

    mock('KMS', 'describeKey', {
      KeyMetadata: { Arn: 'test', KeyManager: 'CUSTOMER' },
    })

    const audits = await handler({ region: 'test' })

    expect(audits).to.eql([
      {
        physicalId: 'test',
        provider: 'aws',
        profile: undefined,
        region: 'test',
        rule: 'SecretEncryptedWithCmk',
        service: 'secrets-manager',
        state: 'OK',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })

  it('should report WARNING for secrets that use AWS managed encryption, not the secrets manager default', async () => {
    mock('SecretsManager', 'listSecrets', {
      SecretList: [{ Name: 'test', KmsKeyId: 'test' }],
    })

    mock('KMS', 'describeKey', {
      KeyMetadata: { Arn: 'test', KeyManager: 'AWS' },
    })

    const audits = await handler({ region: 'test' })

    expect(audits).to.eql([
      {
        physicalId: 'test',
        provider: 'aws',
        profile: undefined,
        region: 'test',
        rule: 'SecretEncryptedWithCmk',
        service: 'secrets-manager',
        state: 'WARNING',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })
})
