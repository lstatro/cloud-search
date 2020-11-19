import {
  AuditResultInterface,
  AWSScannerInterface,
} from '@lstatro/cloud-search'
import assert from 'assert'
import { AWS, keyTypeArg } from '../../../../lib/aws/AWS'
import { SecretListEntry } from 'aws-sdk/clients/secretsmanager'

const rule = 'RotationEnabled'

export const builder = {
  ...keyTypeArg,
}

export const command = `${rule} [args]`

export const desc = `Secrets Manager passwords should have automatic rotation enabled

  OK      - Rotation enabled
  UNKNOWN - Unable to determine if rotation is enabled
  FAIL    - Rotation is not enabled

  resourceId: secret name

`

export class RotationEnabled extends AWS {
  audits: AuditResultInterface[] = []
  service = 'secrets-manager'
  global = false

  constructor(public params: AWSScannerInterface) {
    super({ ...params, rule })
  }

  async audit({
    resource,
    region,
  }: {
    resource: SecretListEntry
    region: string
  }) {
    assert(resource.Name, 'secret must have a name')

    const audit = this.getDefaultAuditObj({
      resource: resource.Name,
      region,
    })

    console.log(resource)

    if (resource.RotationEnabled === true) {
      audit.state = 'OK'
    } else if (resource.RotationEnabled === false) {
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
    const options = this.getOptions()
    options.region = region

    let secrets: SecretListEntry[] = []

    if (resourceId) {
      const describeSecret = await new this.AWS.SecretsManager(options)
        .describeSecret({
          SecretId: resourceId,
        })
        .promise()
      secrets.push(describeSecret)
    } else {
      const promise = new this.AWS.SecretsManager(options)
        .listSecrets()
        .promise()
      secrets = await this.pager<SecretListEntry>(promise, 'SecretList')
    }

    for (const secret of secrets) {
      this.audit({ resource: secret, region })
    }
  }
}

export const handler = async (args: AWSScannerInterface) => {
  const scanner = new RotationEnabled(args)

  await scanner.start()
  scanner.output()
  return scanner.audits
}
