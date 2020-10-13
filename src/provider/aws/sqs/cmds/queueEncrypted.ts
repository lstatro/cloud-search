import { CommandBuilder } from 'yargs'
import {
  AuditResultInterface,
  AWSScannerInterface,
  AWSScannerCliArgsInterface,
} from 'cloud-search'

import AWS from '../../../../lib/aws/AWS'

const rule = 'QueueEncrypted'

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

  OK      - Queue is encrypted
  UNKNOWN - Unable to determine Queue encryption
  WARNING - Queue encrypted but not with the specified key type
  FAIL    - Queue is not encrypted

  resourceId - Queue URL

`

export interface QueueEncryptedInterface extends AWSScannerInterface {
  keyType: 'aws' | 'cmk'
}

export default class TopicEncrypted extends AWS {
  audits: AuditResultInterface[] = []
  service = 'sqs'
  global = false
  keyId?: string
  keyType: 'aws' | 'cmk'

  constructor(public params: QueueEncryptedInterface) {
    super({
      profile: params.profile,
      resourceId: params.resourceId,
      region: params.region,
      rule,
    })
    this.keyType = params.keyType
  }

  async audit({ resourceId, region }: { resourceId: string; region: string }) {
    const options = this.getOptions()
    options.region = region
    const sqs = new this.AWS.SQS(options)
    const getQueueAttributes = await sqs
      .getQueueAttributes({
        QueueUrl: resourceId,
        AttributeNames: ['KmsMasterKeyId'],
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

    /**
     * if we have attributes and that includes the key id attribute.
     * If we don't have attributes we know it's not encrypted
     */
    if (getQueueAttributes.Attributes) {
      if (getQueueAttributes.Attributes.KmsMasterKeyId) {
        const isTrusted = await this.isKeyTrusted(
          getQueueAttributes.Attributes.KmsMasterKeyId,
          this.keyType,
          region
        )
        auditObject.state = isTrusted
      } else {
        auditObject.state = 'FAIL'
      }
    } else {
      auditObject.state = 'FAIL'
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
      const queues = await this.listQueues(region)
      for (const queue of queues) {
        await this.audit({ resourceId: queue, region })
      }
    }
  }
}

export interface QueueEncryptedCliInterface
  extends QueueEncryptedInterface,
    AWSScannerCliArgsInterface {}

export const handler = async (args: QueueEncryptedCliInterface) => {
  const scanner = new TopicEncrypted({
    region: args.region,
    profile: args.profile,
    resourceId: args.resourceId,
    keyType: args.keyType,
  })

  await scanner.start()
  scanner.output()
  return scanner.audits
}
