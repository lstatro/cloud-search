import { CommandBuilder } from 'yargs'
import {
  AuditResultInterface,
  AWSScannerInterface,
} from '@lstatro/cloud-search'
import assert from 'assert'
import { AWS, keyTypeArg } from '../../../../lib/aws/AWS'
import { Topic } from 'aws-sdk/clients/sns'

const rule = 'TopicEncrypted'

export const command = `${rule} [args]`

export const builder: CommandBuilder = {
  ...keyTypeArg,
}

export const desc = `SNS topics must be encrypted

  OK      - Topic is encrypted
  UNKNOWN - Unable to determine topic encryption
  WARNING - Topic encrypted but not with the specified key type
  FAIL    - Topic is not encrypted

  resourceId - Topic ARN

`

export class TopicEncrypted extends AWS {
  audits: AuditResultInterface[] = []
  service = 'sns'
  global = false

  constructor(public params: AWSScannerInterface) {
    super({ ...params, rule })
  }

  async audit({ resource, region }: { resource: string; region: string }) {
    const options = this.getOptions()
    options.region = region

    const sns = new this.AWS.SNS(options)

    const getTopicAttributes = await sns
      .getTopicAttributes({
        TopicArn: resource,
      })
      .promise()

    const audit = this.getDefaultAuditObj({ resource, region })

    if (getTopicAttributes.Attributes) {
      if (getTopicAttributes.Attributes.KmsMasterKeyId) {
        assert(this.keyType, 'key type is required')
        const isTrusted = await this.isKeyTrusted(
          getTopicAttributes.Attributes.KmsMasterKeyId,
          this.keyType,
          region
        )
        audit.state = isTrusted
      } else {
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

      const promise = new this.AWS.SNS(options).listTopics().promise()
      const topics = await this.pager<Topic>(promise, 'Topics')

      for (const topic of topics) {
        assert(topic.TopicArn, 'topic does not have an arn')
        await this.audit({ resource: topic.TopicArn, region })
      }
    }
  }
}

export const handler = async (args: AWSScannerInterface) => {
  const scanner = new TopicEncrypted(args)

  await scanner.start()
  scanner.output()
  return scanner.audits
}
