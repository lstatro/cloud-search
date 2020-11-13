import { CommandBuilder } from 'yargs'
import {
  AuditResultInterface,
  AWSScannerInterface,
} from '@lstatro/cloud-search'
import { AWS, keyTypeArg } from '../../../../lib/aws/AWS'
import assert from 'assert'
import { Bucket, ServerSideEncryptionConfiguration } from 'aws-sdk/clients/s3'

const rule = 'BucketEncryption'

export const command = `${rule} [args]`

export const builder: CommandBuilder = {
  ...keyTypeArg,
}

export const desc = `SQS topics must be encrypted

  OK      - Bucket is encrypted
  UNKNOWN - Unable to determine bucket encryption
  WARNING - Bucket encrypted but not with the specified key type
  FAIL    - Bucket is not encrypted

  resourceId - bucket name

`

export class BucketEncryption extends AWS {
  audits: AuditResultInterface[] = []
  service = 's3'
  global = true

  constructor(public params: AWSScannerInterface) {
    super({ ...params, rule })
  }

  handleAwsKeyType = (
    config: ServerSideEncryptionConfiguration,
    audit: AuditResultInterface
  ) => {
    let isEncryptedWithAes = false

    for (const rule of config.Rules) {
      if (rule.ApplyServerSideEncryptionByDefault?.SSEAlgorithm === 'AES256') {
        isEncryptedWithAes = true
      }
      if (rule.ApplyServerSideEncryptionByDefault?.SSEAlgorithm === 'aws:kms') {
        isEncryptedWithAes = true
      }
    }

    if (isEncryptedWithAes) {
      audit.state = 'OK'
    } else {
      audit.state = 'FAIL'
    }
  }

  handleCmkKeyType = async (
    config: ServerSideEncryptionConfiguration,
    audit: AuditResultInterface,
    region: string
  ) => {
    let isEncrypted = false
    for (const rule of config.Rules) {
      if (rule.ApplyServerSideEncryptionByDefault?.SSEAlgorithm === 'AES256') {
        isEncrypted = true
        audit.state = 'WARNING'
      }
      if (rule.ApplyServerSideEncryptionByDefault?.KMSMasterKeyID) {
        isEncrypted = true
        assert(this.keyType, 'key type is required')
        audit.state = await this.isKeyTrusted(
          rule.ApplyServerSideEncryptionByDefault.KMSMasterKeyID,
          this.keyType,
          region
        )
      }
    }
    if (isEncrypted === false) {
      audit.state = 'FAIL'
    }
  }

  async audit({ resource, region }: { resource: string; region: string }) {
    const options = this.getOptions()
    const s3 = new this.AWS.S3(options)

    const audit = this.getDefaultAuditObj({ resource, region })

    try {
      const getBucket = await s3
        .getBucketEncryption({
          Bucket: resource,
        })
        .promise()

      if (getBucket.ServerSideEncryptionConfiguration) {
        if (this.keyType === 'aws') {
          this.handleAwsKeyType(
            getBucket.ServerSideEncryptionConfiguration,
            audit
          )
        } else if (this.keyType === 'cmk') {
          await this.handleCmkKeyType(
            getBucket.ServerSideEncryptionConfiguration,
            audit,
            region
          )
        } else {
          throw 'unsupported key type'
        }
      } else {
        audit.state = 'FAIL'
      }
    } catch (err) {
      if (err.code === 'ServerSideEncryptionConfigurationNotFoundError') {
        audit.state = 'FAIL'
      }
    }

    this.audits.push(audit)
  }

  scan = async ({
    resourceId,
    region,
  }: {
    resourceId: string
    region: string
  }) => {
    if (resourceId) {
      await this.audit({ resource: resourceId, region })
    } else {
      const options = this.getOptions()
      options.region = region

      const promise = new this.AWS.S3(options).listBuckets().promise()
      const buckets = await this.pager<Bucket>(promise, 'Buckets')

      for (const bucket of buckets) {
        assert(bucket.Name, 'bucket must have a name')
        await this.audit({ resource: bucket.Name, region })
      }
    }
  }
}

export const handler = async (args: AWSScannerInterface) => {
  const scanner = new BucketEncryption(args)

  await scanner.start()
  scanner.output()
  return scanner.audits
}
