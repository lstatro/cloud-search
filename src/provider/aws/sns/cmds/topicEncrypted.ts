import { CommandBuilder } from 'yargs'
import { AuditResultInterface, AWSScannerInterface } from 'cloud-search'
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
}

export const desc = `SNS topics must be encrypted

  OK      - Topic is encrypted
  UNKNOWN - Unable to determine topic encryption
  WARNING - Topic encrypted but not with the specified key type
  FAIL    - Topic is not encrypted

  resourceId - Topic ARN

`

export interface TopicEncryptedInterface extends AWSScannerInterface {
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
      region: params.region,
      verbosity: params.verbosity,
      rule,
    })
    this.keyType = params.keyType
  }

  async audit({ resourceId, region }: { resourceId: string; region: string }) {
    const options = this.getOptions()
    options.region = region

    const sns = new this.AWS.SNS(options)

    const getTopicAttributes = await sns
      .getTopicAttributes({
        TopicArn: resourceId,
      })
      .promise()

    const auditObject: AuditResultInterface = {
      name: resourceId,
      provider: 'aws',
      physicalId: resourceId,
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
          region
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
      await this.audit({ resourceId, region })
    } else {
      const topics = await this.listTopics(region)
      for (const topic of topics) {
        assert(topic.TopicArn, 'topic does not have an arn')
        await this.audit({ resourceId: topic.TopicArn, region })
      }
    }
  }
}

export const handler = async (args: TopicEncryptedInterface) => {
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
