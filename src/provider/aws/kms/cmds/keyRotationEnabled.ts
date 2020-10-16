/** TODO: can this be handled by iam.simulatePrincipalPolicy? */

import { AuditResultInterface, AWSScannerInterface } from 'cloud-search'
import AWS from '../../../../lib/aws/AWS'
import assert from 'assert'
const rule = 'KeyRotationEnabled'

export const command = `${rule} [args]`

export const desc = `AWS managed customer keys (CMK's) should have yearly rotation enabled

  OK      - yearly rotation enabled
  UNKNOWN - unable to determine if yearly rotation is enabled
  FAIL    - yearly rotation is not enabled

  resourceId: KMS Key ID

`

export default class KeyRotationEnabled extends AWS {
  audits: AuditResultInterface[] = []
  service = 'kms'
  global = false

  constructor(public params: AWSScannerInterface) {
    super({
      profile: params.profile,
      resourceId: params.resourceId,
      region: params.region,
      verbosity: params.verbosity,
      rule,
    })
  }

  async audit({ resource, region }: { resource: string; region: string }) {
    const options = this.getOptions()
    options.region = region

    const kms = new this.AWS.KMS(options)

    const describeKey = await kms.describeKey({ KeyId: resource }).promise()

    assert(describeKey.KeyMetadata, 'key does not have metadata')

    /** we only care about customer keys, we want to ignore AWS managed keys entirely as we cannot rotate them */
    if (describeKey.KeyMetadata.KeyManager === 'CUSTOMER') {
      const audit: AuditResultInterface = {
        provider: 'aws',
        physicalId: resource,
        service: this.service,
        rule: this.rule,
        region: region,
        state: 'UNKNOWN',
        profile: this.profile,
        time: new Date().toISOString(),
      }

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

  scan = async ({ resource, region }: { resource: string; region: string }) => {
    if (resource) {
      await this.audit({ resource, region })
    } else {
      const keys = await this.listKeys(region)
      for (const key of keys) {
        assert(key.KeyArn, 'key missing its key ARN')
        await this.audit({ resource: key.KeyArn, region })
      }
    }
  }
}

export const handler = async (args: AWSScannerInterface) => {
  const scanner = new KeyRotationEnabled({
    region: args.region,
    profile: args.profile,
    resourceId: args.resourceId,
    verbosity: args.verbosity,
  })
  await scanner.start()
  scanner.output()
  return scanner.audits
}
