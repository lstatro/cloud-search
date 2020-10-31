import { AuditResultInterface, AWSScannerInterface } from 'cloud-search'
import { AWS } from '../../../../lib/aws/AWS'
import assert from 'assert'
// import { KeyListEntry } from 'aws-sdk/clients/kms'
const rule = 'NeptuneEncryptionEnabled'

export const command = `${rule} [args]`

export const desc = `Amazon Neptune graph databases should have encryption enabled

  OK      - Encryption enabled
  UNKNOWN - Unable to determine if encryption enabled
  FAIL    - Encryption not enabled

  resourceId: Unkown

`
//TODO: Figure out the resourceId for Neptune.

export default class NeptuneEncryptionEnabled extends AWS {
  audits: AuditResultInterface[] = []
  service = 'neptune'
  global = false

  constructor(public params: AWSScannerInterface) {
    super({ ...params, rule })
  }

  async audit({ resource, region }: { resource: string; region: string }) {
    const options = this.getOptions()
    options.region = region
    const neptune = new this.AWS.Neptune(options)
    // TODO: API call to audit the neptune instance for encryption enabled
    // determine the audit state and then push the state.
    const audit = this.getDefaultAuditObj({ resource, region })
    audit.state = 'OK'
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

      // const promise = new this.AWS.Neptune(options).listKeys().promise()
      // const keys = await this.pager<KeyListEntry>(promise, 'Keys')

      // for (const key of keys) {
      //   assert(key.KeyArn, 'key missing its key ARN')
      //   await this.audit({ resource: key.KeyArn, region })
      // }
    }
  }
}

export const handler = async (args: AWSScannerInterface) => {
  const scanner = new NeptuneEncryptionEnabled(args)
  await scanner.start()
  scanner.output()
  return scanner.audits
}
