import { AWS, keyTypeArg } from '../../../../lib/aws/AWS'
import {
  AWSScannerInterface,
  AuditResultInterface,
} from '@lstatro/cloud-search'

import { CommandBuilder } from 'yargs'
import { Topic } from 'aws-sdk/clients/sns'
import assert from 'assert'

const rule = 'TopicEncrypted'

export const command = `${rule} [args]`

export const builder: CommandBuilder = {
  ...keyTypeArg,
}

export const desc = `SNS topics must have encryption at rest enabled

  OK      - Topic is encrypted
  UNKNOWN - Unable to determine topic encryption
  WARNING - Topic encrypted but not with the specified key type
  FAIL    - Topic is not encrypted

  resource - Topic ARN

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

  scan = async ({ resource, region }: { resource: string; region: string }) => {
    if (resource) {
      await this.audit({ resource: resource, region })
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
