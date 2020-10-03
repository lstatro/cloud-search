/**
 * - TODO: ddd support for encryption level of AWS and or CMK keys not what it
 * is now of just "any"
 * - TODO: support alias and key arns
 */

import { CommandBuilder } from 'yargs'
import {
  AuditResultInterface,
  AWSScannerInterface,
  AWSScannerCliArgsInterface,
} from 'cloud-search'
import assert from 'assert'
import AWS from '../../../../lib/aws/AWS'

const rule = 'TopicEncrypted'

export const command = `${rule} [args]`

export const builder: CommandBuilder = {
  keyType: {
    alias: 't',
    describe: 'the AWS key type',
    type: 'string',
    default: 'aws',
    choices: ['aws', 'cmk'],
  },
  keyId: {
    describe: 'a KMS key arn',
    type: 'string',
  },
}

export const desc = `SNS topics must be encrypted

  OK      - Topic is encrypted
  UNKNOWN - unable to determine topic encryption
  FAIL    - topic is not encrypted

  resourceId - Topic ARN

`

export interface TopicEncryptedInterface extends AWSScannerInterface {
  keyId?: string
  keyType: 'aws' | 'cmk'
}

export default class TopicEncrypted extends AWS {
  audits: AuditResultInterface[] = []
  service = 'sns'
  global = false
  keyId?: string
  keyType: 'aws' | 'cmk'

  constructor(public params: TopicEncryptedInterface) {
    super({
      profile: params.profile,
      resourceId: params.resourceId,
      domain: params.domain,
      region: params.region,
      rule,
    })
    this.keyId = params.keyId
    this.keyType = params.keyType
  }

  async audit(topicArn: string, region: string) {
    const options = this.getOptions()
    options.region = region

    const sns = new this.AWS.SNS(options)

    const getTopicAttributes = await sns
      .getTopicAttributes({
        TopicArn: topicArn,
      })
      .promise()

    // const describeKey = await new this.AWS.KMS(options)
    //   .describeKey({
    //     KeyId:
    //       'arn:aws:kms:us-east-1:814535775158:key/19368815-24d1-4efa-8a72-4f3b32d81c16',
    //     // KeyId:
    //     // 'arn:aws:kms:us-east-1:814535775158:key/19368815-24d1-4efa-8a72-4f3b32d81c16',
    //   })
    //   .promise()

    // console.log(describeKey.KeyMetadata)

    const auditObject: AuditResultInterface = {
      name: topicArn,
      provider: 'aws',
      physicalId: topicArn,
      service: this.service,
      rule: this.rule,
      region: region,
      state: 'UNKNOWN',
      profile: this.profile,
      time: new Date().toISOString(),
    }

    if (getTopicAttributes.Attributes) {
      if (getTopicAttributes.Attributes.KmsMasterKeyId) {
        const isTrusted = await this.isKeyTrusted(
          getTopicAttributes.Attributes.KmsMasterKeyId,
          this.keyType,
          region,
          this.keyId
        )
        auditObject.state = isTrusted
      } else {
        auditObject.state = 'FAIL'
      }
    }

    this.audits.push(auditObject)
  }

  scan = async ({
    region,
    resourceId,
  }: {
    region: string
    resourceId: string
  }) => {
    if (resourceId) {
      await this.audit(resourceId, region)
    } else {
      const topics = await this.listTopics(region)
      for (const topic of topics) {
        assert(topic.TopicArn, 'topic does not have an arn')
        await this.audit(topic.TopicArn, region)
      }
    }
  }
}

export interface TopicEncryptedCliInterface
  extends TopicEncryptedInterface,
    AWSScannerCliArgsInterface {}

export const handler = async (args: TopicEncryptedCliInterface) => {
  const scanner = new TopicEncrypted({
    region: args.region,
    profile: args.profile,
    resourceId: args.resourceId,
    domain: args.domain,
    keyType: args.keyType,
    keyId: args.keyId,
  })

  await scanner.start()
  scanner.output()
  return scanner.audits
}
