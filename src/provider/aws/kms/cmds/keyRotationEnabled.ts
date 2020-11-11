import {
  AuditResultInterface,
  AWSScannerInterface,
} from '@lstatro/cloud-search'
import { AWS } from '../../../../lib/aws/AWS'
import assert from 'assert'
import { KeyListEntry } from 'aws-sdk/clients/kms'
const rule = 'KeyRotationEnabled'

export const command = `${rule} [args]`

export const desc = `AWS managed customer keys (CMK's) should have yearly rotation enabled

  OK      - Yearly rotation enabled
  UNKNOWN - Unable to determine if yearly rotation is enabled
  FAIL    - Yearly rotation is not enabled

  resourceId: KMS Key ID

`

export default class KeyRotationEnabled extends AWS {
  audits: AuditResultInterface[] = []
  service = 'kms'
  global = false

  constructor(public params: AWSScannerInterface) {
    super({ ...params, rule })
  }

  async audit({ resource, region }: { resource: string; region: string }) {
    const options = this.getOptions()
    options.region = region

    const kms = new this.AWS.KMS(options)

    const describeKey = await kms.describeKey({ KeyId: resource }).promise()

    assert(describeKey.KeyMetadata, 'key does not have metadata')

    /** we only care about customer keys, we want to ignore AWS managed keys entirely as we cannot rotate them */
    if (describeKey.KeyMetadata.KeyManager === 'CUSTOMER') {
      const audit = this.getDefaultAuditObj({ resource, region })

      const getKeyRotationStatus = await kms
        .getKeyRotationStatus({
          KeyId: resource,
        })
        .promise()

      if (getKeyRotationStatus.KeyRotationEnabled === true) {
        audit.state = 'OK'
      } else if (getKeyRotationStatus.KeyRotationEnabled === false) {
        audit.state = 'FAIL'
      }

      this.audits.push(audit)
    }
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

      const promise = new this.AWS.KMS(options).listKeys().promise()
      const keys = await this.pager<KeyListEntry>(promise, 'Keys')

      for (const key of keys) {
        assert(key.KeyArn, 'key missing its key ARN')
        await this.audit({ resource: key.KeyArn, region })
      }
    }
  }
}

export const handler = async (args: AWSScannerInterface) => {
  const scanner = new KeyRotationEnabled(args)
  await scanner.start()
  scanner.output()
  return scanner.audits
}
