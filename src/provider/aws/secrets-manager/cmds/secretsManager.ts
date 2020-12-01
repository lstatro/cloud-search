import {
  AuditResultInterface,
  AWSScannerInterface,
} from '@lstatro/cloud-search'
import assert from 'assert'
import { AWS } from '../../../../lib/aws/AWS'
import { SecretListEntry } from 'aws-sdk/clients/secretsmanager'

export interface SecretsManagerInterface extends AWSScannerInterface {
  rule: 'RotationEnabled' | 'SecretEncryptedWithCmk'
}

export class SecretsManager extends AWS {
  audits: AuditResultInterface[] = []
  service = 'secrets-manager'
  global = false

  constructor(public params: SecretsManagerInterface) {
    super({ ...params })
  }

  handleRotationEnabled = ({
    resource,
    audit,
  }: {
    resource: SecretListEntry
    audit: AuditResultInterface
  }) => {
    if (resource.RotationEnabled === true) {
      audit.state = 'OK'
    } else {
      audit.state = 'FAIL'
    }

    this.audits.push(audit)
  }

  handleSecretEncryptedWithCmk = async ({
    resource,
    audit,
    region,
  }: {
    resource: SecretListEntry
    audit: AuditResultInterface
    region: string
  }) => {
    console.log(resource)

    if (resource.KmsKeyId) {
      audit.state = await this.isKeyTrusted(resource.KmsKeyId, 'cmk', region)
    } else {
      audit.state = 'FAIL'
    }

    this.audits.push(audit)
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

    const rules: {
      [key: string]: ({
        resource,
        audit,
        region,
      }: {
        resource: SecretListEntry
        audit: AuditResultInterface
        region: string
      }) => void
    } = {
      RotationEnabled: this.handleRotationEnabled,
      SecretEncryptedWithCmk: this.handleSecretEncryptedWithCmk,
    }

    if (rules[this.rule]) {
      await rules[this.rule]({ resource, audit, region })
    }
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
      await this.audit({ resource: secret, region })
    }
  }
}
