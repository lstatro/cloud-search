/**
 * - TODO: ddd support for encryption level of AWS and or CMK keys not what it
 * is now of just "any"
 * - TODO: support alias and key arns
 */

import {
  AuditResultInterface,
  AWSScannerInterface,
  AWSScannerCliArgsInterface,
} from 'cloud-search'
import assert from 'assert'
import AWS from '../../../../lib/aws/AWS'

const rule = 'TopicEncrypted'

export const command = `${rule} [args]`

export const desc = `SNS topics must be encrypted

  OK      - Topic is encrypted
  UNKNOWN - unable to determine topic encryption
  FAIL    - topic is not encrypted

  resourceId - Topic ARN

`

export default class TopicEncrypted extends AWS {
  audits: AuditResultInterface[] = []
  service = 'sns'
  global = false

  constructor(public params: AWSScannerInterface) {
    super({
      profile: params.profile,
      resourceId: params.resourceId,
      domain: params.domain,
      region: params.region,
      rule,
    })
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
        auditObject.state = 'OK'
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

export const handler = async (args: AWSScannerCliArgsInterface) => {
  const scanner = new TopicEncrypted({
    region: args.region,
    profile: args.profile,
    resourceId: args.resourceId,
    domain: args.domain,
  })

  await scanner.start()
  scanner.output()
  return scanner.audits
}
