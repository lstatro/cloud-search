import { CommandBuilder } from 'yargs'
import {
  AuditResultInterface,
  AWSScannerInterface,
  AWSScannerCliArgsInterface,
} from 'cloud-search'

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
    auditObject: AuditResultInterface
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
      auditObject.state = 'OK'
    } else {
      auditObject.state = 'FAIL'
    }
  }

  handleCmkKeyType = async (
    config: ServerSideEncryptionConfiguration,
    auditObject: AuditResultInterface,
    region: string
  ) => {
    let isEncrypted = false
    for (const rule of config.Rules) {
      if (rule.ApplyServerSideEncryptionByDefault?.SSEAlgorithm === 'AES256') {
        isEncrypted = true
        auditObject.state = 'WARNING'
      }
      if (rule.ApplyServerSideEncryptionByDefault?.KMSMasterKeyID) {
        isEncrypted = true
        auditObject.state = await this.isKeyTrusted(
          rule.ApplyServerSideEncryptionByDefault.KMSMasterKeyID,
          this.keyType,
          region
        )
      }
    }
    if (isEncrypted === false) {
      auditObject.state = 'FAIL'
    }
  }

  async audit({ resource, region }: { resource: string; region: string }) {
    const options = this.getOptions()
    const s3 = new this.AWS.S3(options)

    const auditObject: AuditResultInterface = {
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
            auditObject
          )
        } else if (this.keyType === 'cmk') {
          await this.handleCmkKeyType(
            getBucket.ServerSideEncryptionConfiguration,
            auditObject,
            region
          )
        } else {
          throw 'unsupported key type'
        }
      } else {
        auditObject.state = 'FAIL'
      }
    } catch (err) {
      if (err.code === 'ServerSideEncryptionConfigurationNotFoundError') {
        auditObject.state = 'FAIL'
      }
    }

    this.audits.push(auditObject)
  }

  scan = async ({ region, resource }: { region: string; resource: string }) => {
    if (resource) {
      await this.audit({ resource, region })
    } else {
      const buckets = await this.listBuckets()
      for (const bucket of buckets) {
        assert(bucket.Name, 'bucket must have a name')
        await this.audit({ resource: bucket.Name, region })
      }
    }
  }
}

export interface BucketEncryptedCliInterface
  extends BucketEncryptedInterface,
    AWSScannerCliArgsInterface {}

export const handler = async (args: BucketEncryptedCliInterface) => {
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
