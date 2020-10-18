import { CommandBuilder } from 'yargs'
import { AuditResultInterface, AWSScannerInterface } from 'cloud-search'
import { AWS, keyTypeArg } from '../../../../lib/aws/AWS'
import assert from 'assert'

const rule = 'QueueEncrypted'

export const command = `${rule} [args]`

export const builder: CommandBuilder = {
  ...keyTypeArg,
}

export const desc = `SQS topics must be encrypted

  OK      - Queue is encrypted
  UNKNOWN - Unable to determine Queue encryption
  WARNING - Queue encrypted but not with the specified key type
  FAIL    - Queue is not encrypted

  resourceId - Queue URL

`

export default class TopicEncrypted extends AWS {
  audits: AuditResultInterface[] = []
  service = 'sqs'
  global = false
  keyId?: string

  constructor(public params: AWSScannerInterface) {
    super({
      profile: params.profile,
      resourceId: params.resourceId,
      region: params.region,
      verbosity: params.verbosity,
      rule,
    })
    this.keyType = params.keyType
  }

  async audit({ resource, region }: { resource: string; region: string }) {
    const options = this.getOptions()
    options.region = region
    const sqs = new this.AWS.SQS(options)
    const getQueueAttributes = await sqs
      .getQueueAttributes({
        QueueUrl: resource,
        AttributeNames: ['KmsMasterKeyId'],
      })
      .promise()
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

    /**
     * if we have attributes and that includes the key id attribute.
     * If we don't have attributes we know it's not encrypted
     */
    if (getQueueAttributes.Attributes) {
      if (getQueueAttributes.Attributes.KmsMasterKeyId) {
        assert(this.keyType, 'key type is required')
        const isTrusted = await this.isKeyTrusted(
          getQueueAttributes.Attributes.KmsMasterKeyId,
          this.keyType,
          region
        )
        audit.state = isTrusted
      } else {
        audit.state = 'FAIL'
      }
    } else {
      audit.state = 'FAIL'
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
      const queues = await this.listQueues(region)
      for (const queue of queues) {
        await this.audit({ resource: queue, region })
      }
    }
  }
}

export const handler = async (args: AWSScannerInterface) => {
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
