import { CommandBuilder } from 'yargs'
import { AuditResultInterface, AWSScannerInterface } from 'cloud-search'

import AWS from '../../../../lib/aws/AWS'
import assert from 'assert'
import { ServerSideEncryptionConfiguration } from 'aws-sdk/clients/s3'

const rule = 'BucketEncryption'

export const command = `${rule} [args]`

export const builder: CommandBuilder = {
  keyType: {
    alias: 't',
    describe: 'the AWS key type',
    type: 'string',
    default: 'aws',
    choices: ['aws', 'cmk'],
  },
}

export const desc = `SQS topics must be encrypted

  OK      - Bucket is encrypted
  UNKNOWN - Unable to determine bucket encryption
  WARNING - Bucket encrypted but not with the specified key type
  FAIL    - Bucket is not encrypted

  resourceId - bucket name

`

export interface BucketEncryptedInterface extends AWSScannerInterface {
  keyType: 'aws' | 'cmk'
}

export default class TopicEncrypted extends AWS {
  audits: AuditResultInterface[] = []
  service = 's3'
  global = true
  keyType: 'aws' | 'cmk'

  constructor(public params: BucketEncryptedInterface) {
    super({
      profile: params.profile,
      resourceId: params.resourceId,
      region: params.region,
      verbosity: params.verbosity,
      rule,
    })
    this.keyType = params.keyType
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

    const audit: AuditResultInterface = {
      name: resource,
      provider: 'aws',
      physicalId: resource,
      service: this.service,
      rule: this.rule,
      region: region,
      state: 'UNKNOWN',
      profile: this.profile,
      time: new Date().toISOString(),
    }

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
      const buckets = await this.listBuckets()
      for (const bucket of buckets) {
        assert(bucket.Name, 'bucket must have a name')
        await this.audit({ resource: bucket.Name, region })
      }
    }
  }
}

export const handler = async (args: BucketEncryptedInterface) => {
  const scanner = new TopicEncrypted({
    region: args.region,
    profile: args.profile,
    resourceId: args.resourceId,
    keyType: args.keyType,
    verbosity: args.verbosity,
  })

  await scanner.start()
  scanner.output()
  return scanner.audits
}
