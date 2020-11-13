import { CommandBuilder } from 'yargs'
import {
  AuditResultInterface,
  AWSScannerInterface,
} from '@lstatro/cloud-search'
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

export class QueueEncrypted extends AWS {
  audits: AuditResultInterface[] = []
  service = 'sqs'
  global = false

  constructor(public params: AWSScannerInterface) {
    super({ ...params, rule })
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

    const audit = this.getDefaultAuditObj({ resource, region })

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
      const options = this.getOptions()
      options.region = region

      const promise = new this.AWS.SQS(options).listQueues().promise()
      const queues = await this.pager<string>(promise, 'QueueUrls')

      for (const queue of queues) {
        await this.audit({ resource: queue, region })
      }
    }
  }
}

export const handler = async (args: AWSScannerInterface) => {
  const scanner = new QueueEncrypted(args)

  await scanner.start()
  scanner.output()
  return scanner.audits
}
