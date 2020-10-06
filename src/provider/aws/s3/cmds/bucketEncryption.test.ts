import 'mocha'
import { mock, restore } from 'aws-sdk-mock'
import { useFakeTimers, SinonFakeTimers } from 'sinon'
import { handler, BucketEncryptedCliInterface } from './bucketEncryption'
import { expect } from 'chai'
import { AWSError } from 'aws-sdk'
describe('iam user key age', () => {
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

  it('should report FAIL for buckets with no encryption', async () => {
    mock('S3', 'listBuckets', {
      Buckets: [
        {
          Name: 'test',
        },
      ],
    })
    mock('S3', 'getBucketEncryption', {
      ServerSideEncryptionConfiguration: {
        Rules: [],
      },
    })
    const audits = await handler({
      resourceId: 'test',
      domain: 'pub',
      region: 'test',
      keyType: 'aws',
    } as BucketEncryptedCliInterface)

    expect(audits).to.eql([
      {
        name: 'test',
        provider: 'aws',
        physicalId: 'test',
        service: 's3',
        rule: 'BucketEncryption',
        region: 'test',
        state: 'FAIL',
        profile: undefined,
        time: now.toISOString(),
      },
    ])
  })

  it('should report FAIL for buckets with no encryption', async () => {
    mock('S3', 'listBuckets', {
      Buckets: [
        {
          Name: 'test',
        },
      ],
    })
    mock('S3', 'getBucketEncryption', {
      ServerSideEncryptionConfiguration: {
        Rules: [],
      },
    })
    const audits = await handler({
      resourceId: 'test',
      domain: 'pub',
      region: 'test',
      keyType: 'cmk',
    } as BucketEncryptedCliInterface)

    expect(audits).to.eql([
      {
        name: 'test',
        provider: 'aws',
        physicalId: 'test',
        service: 's3',
        rule: 'BucketEncryption',
        region: 'test',
        state: 'FAIL',
        profile: undefined,
        time: now.toISOString(),
      },
    ])
  })

  it('should report OK for aws key requests of buckets that are encrypted', async () => {
    mock('S3', 'listBuckets', {
      Buckets: [
        {
          Name: 'test',
        },
      ],
    })
    mock('S3', 'getBucketEncryption', {
      ServerSideEncryptionConfiguration: {
        Rules: [
          {
            ApplyServerSideEncryptionByDefault: {
              SSEAlgorithm: 'AES256',
            },
          },
        ],
      },
    })
    const audits = await handler({
      domain: 'pub',
      region: 'test',
      keyType: 'aws',
    } as BucketEncryptedCliInterface)

    expect(audits).to.eql([
      {
        name: 'test',
        provider: 'aws',
        physicalId: 'test',
        service: 's3',
        rule: 'BucketEncryption',
        region: 'test',
        state: 'OK',
        profile: undefined,
        time: now.toISOString(),
      },
    ])
  })

  it('should report FAIL for aws key requests of buckets that lack the ApplyServerSideEncryptionByDefault attribute', async () => {
    mock('S3', 'listBuckets', {
      Buckets: [
        {
          Name: 'test',
        },
      ],
    })
    mock('S3', 'getBucketEncryption', {
      ServerSideEncryptionConfiguration: {
        Rules: [{}],
      },
    })
    const audits = await handler({
      domain: 'pub',
      region: 'test',
      keyType: 'aws',
    } as BucketEncryptedCliInterface)

    expect(audits).to.eql([
      {
        name: 'test',
        provider: 'aws',
        physicalId: 'test',
        service: 's3',
        rule: 'BucketEncryption',
        region: 'test',
        state: 'FAIL',
        profile: undefined,
        time: now.toISOString(),
      },
    ])
  })

  it('should report FAIL for aws key requests of buckets that lack the SSEAlgorithm', async () => {
    mock('S3', 'listBuckets', {
      Buckets: [
        {
          Name: 'test',
        },
      ],
    })
    mock('S3', 'getBucketEncryption', {
      ServerSideEncryptionConfiguration: {
        Rules: [
          {
            ApplyServerSideEncryptionByDefault: {},
          },
        ],
      },
    })
    const audits = await handler({
      domain: 'pub',
      region: 'test',
      keyType: 'aws',
    } as BucketEncryptedCliInterface)

    expect(audits).to.eql([
      {
        name: 'test',
        provider: 'aws',
        physicalId: 'test',
        service: 's3',
        rule: 'BucketEncryption',
        region: 'test',
        state: 'FAIL',
        profile: undefined,
        time: now.toISOString(),
      },
    ])
  })

  it('should report OK for aws key requests of buckets that are encrypted', async () => {
    mock('S3', 'listBuckets', {
      Buckets: [
        {
          Name: 'test',
        },
      ],
    })
    mock('S3', 'getBucketEncryption', {
      ServerSideEncryptionConfiguration: {
        Rules: [
          {
            ApplyServerSideEncryptionByDefault: {
              SSEAlgorithm: 'aws:kms',
            },
          },
        ],
      },
    })
    const audits = await handler({
      domain: 'pub',
      region: 'test',
      keyType: 'aws',
    } as BucketEncryptedCliInterface)

    expect(audits).to.eql([
      {
        name: 'test',
        provider: 'aws',
        physicalId: 'test',
        service: 's3',
        rule: 'BucketEncryption',
        region: 'test',
        state: 'OK',
        profile: undefined,
        time: now.toISOString(),
      },
    ])
  })

  it('should report OK for cmk key requests of buckets that are encrypted', async () => {
    mock('S3', 'listBuckets', {
      Buckets: [
        {
          Name: 'test',
        },
      ],
    })
    mock('S3', 'getBucketEncryption', {
      ServerSideEncryptionConfiguration: {
        Rules: [
          {
            ApplyServerSideEncryptionByDefault: {
              SSEAlgorithm: 'aws:kms',
              KMSMasterKeyID: 'test',
            },
          },
        ],
      },
    })
    mock('KMS', 'describeKey', {
      KeyMetadata: { Arn: 'test', KeyManager: 'CUSTOMER' },
    })
    const audits = await handler({
      domain: 'pub',
      region: 'test',
      keyType: 'cmk',
    } as BucketEncryptedCliInterface)

    expect(audits).to.eql([
      {
        name: 'test',
        provider: 'aws',
        physicalId: 'test',
        service: 's3',
        rule: 'BucketEncryption',
        region: 'test',
        state: 'OK',
        profile: undefined,
        time: now.toISOString(),
      },
    ])
  })

  it('should report WARNING for cmk key requests of buckets that are encrypted with AES256', async () => {
    mock('S3', 'listBuckets', {
      Buckets: [
        {
          Name: 'test',
        },
      ],
    })
    mock('S3', 'getBucketEncryption', {
      ServerSideEncryptionConfiguration: {
        Rules: [
          {
            ApplyServerSideEncryptionByDefault: {
              SSEAlgorithm: 'AES256',
              // KMSMasterKeyID: 'test',
            },
          },
        ],
      },
    })
    mock('KMS', 'describeKey', {
      KeyMetadata: { Arn: 'test', KeyManager: 'CUSTOMER' },
    })
    const audits = await handler({
      domain: 'pub',
      region: 'test',
      keyType: 'cmk',
    } as BucketEncryptedCliInterface)

    expect(audits).to.eql([
      {
        name: 'test',
        provider: 'aws',
        physicalId: 'test',
        service: 's3',
        rule: 'BucketEncryption',
        region: 'test',
        state: 'WARNING',
        profile: undefined,
        time: now.toISOString(),
      },
    ])
  })

  it('should report FAIL for cmk key requests of buckets that are not encrypted', async () => {
    mock('S3', 'listBuckets', {
      Buckets: [
        {
          Name: 'test',
        },
      ],
    })
    mock('S3', 'getBucketEncryption', {
      ServerSideEncryptionConfiguration: {
        Rules: [{}],
      },
    })
    mock('KMS', 'describeKey', {
      KeyMetadata: { Arn: 'test', KeyManager: 'CUSTOMER' },
    })
    const audits = await handler({
      domain: 'pub',
      region: 'test',
      keyType: 'cmk',
    } as BucketEncryptedCliInterface)

    expect(audits).to.eql([
      {
        name: 'test',
        provider: 'aws',
        physicalId: 'test',
        service: 's3',
        rule: 'BucketEncryption',
        region: 'test',
        state: 'FAIL',
        profile: undefined,
        time: now.toISOString(),
      },
    ])
  })

  it('should report FAIL for cmk key requests of buckets that are not encrypted', async () => {
    mock('S3', 'listBuckets', {
      Buckets: [
        {
          Name: 'test',
        },
      ],
    })
    mock('S3', 'getBucketEncryption', {})
    const audits = await handler({
      domain: 'pub',
      region: 'test',
      keyType: 'cmk',
    } as BucketEncryptedCliInterface)

    expect(audits).to.eql([
      {
        name: 'test',
        provider: 'aws',
        physicalId: 'test',
        service: 's3',
        rule: 'BucketEncryption',
        region: 'test',
        state: 'FAIL',
        profile: undefined,
        time: now.toISOString(),
      },
    ])
  })

  it('should report UNKNOWN unsupported key types', async () => {
    mock('S3', 'listBuckets', {
      Buckets: [
        {
          Name: 'test',
        },
      ],
    })
    mock('S3', 'getBucketEncryption', {
      ServerSideEncryptionConfiguration: {
        Rules: [{}],
      },
    })
    mock('S3', 'getBucketEncryption', {})
    const audits = await handler({
      domain: 'pub',
      region: 'test',
      keyType: 'test' as 'aws',
    } as BucketEncryptedCliInterface)

    expect(audits).to.eql([
      {
        name: 'test',
        provider: 'aws',
        physicalId: 'test',
        service: 's3',
        rule: 'BucketEncryption',
        region: 'test',
        state: 'UNKNOWN',
        profile: undefined,
        time: now.toISOString(),
      },
    ])
  })

  it('should report FAIL for buckets with ServerSideEncryptionConfigurationNotFoundError errors', async () => {
    const err = new Error('test') as AWSError
    err.code = 'ServerSideEncryptionConfigurationNotFoundError'
    mock('S3', 'listBuckets', {
      Buckets: [
        {
          Name: 'test',
        },
      ],
    })
    mock('S3', 'getBucketEncryption', Promise.reject(err))
    const audits = await handler({
      domain: 'pub',
      region: 'test',
      keyType: 'test' as 'aws',
    } as BucketEncryptedCliInterface)

    expect(audits).to.eql([
      {
        name: 'test',
        provider: 'aws',
        physicalId: 'test',
        service: 's3',
        rule: 'BucketEncryption',
        region: 'test',
        state: 'FAIL',
        profile: undefined,
        time: now.toISOString(),
      },
    ])
  })
})
