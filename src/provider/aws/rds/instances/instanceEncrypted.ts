import { CommandBuilder } from 'yargs'
import { AuditResultInterface, AWSScannerInterface } from 'cloud-search'
import assert from 'assert'
import AWS from '../../../../lib/aws/AWS'
import { DBInstance } from 'aws-sdk/clients/rds'

const rule = 'InstanceEncrypted'

export const builder: CommandBuilder = {
  keyType: {
    alias: 't',
    describe: 'the AWS key type',
    type: 'string',
    default: 'aws',
    choices: ['aws', 'cmk'],
  },
}

export const command = `${rule} [args]`

export const desc = `RDS instances must not have the PubliclyAccessible flag set to true

  OK      - the RDS instance has PubliclyAccessible set to false
  UNKNOWN - unable to verify the public state of the instance
  FAIL    - the RDS instance has PubliclyAccessible set to true, meaning it's public

  resourceId: RDS instance ARN

  note: this rule targets DB Instances not DB Cluster's (Aurora clusters).

`

export interface InstanceEncryptedInterface extends AWSScannerInterface {
  keyType: 'aws' | 'cmk'
}

export default class PublicInstance extends AWS {
  audits: AuditResultInterface[] = []
  service = 'rds'
  global = false
  keyType: 'aws' | 'cmk'

  constructor(public params: InstanceEncryptedInterface) {
    super({
      profile: params.profile,
      resourceId: params.resourceId,
      region: params.region,
      verbosity: params.verbosity,
      rule,
    })
    this.keyType = params.keyType
  }

  async audit({ resource, region }: { resource: DBInstance; region: string }) {
    assert(resource.DBInstanceArn, 'instance does not have an instance ARN')
    const audit: AuditResultInterface = {
      provider: 'aws',
      physicalId: resource.DBInstanceArn,
      service: this.service,
      rule: this.rule,
      region: region,
      state: 'UNKNOWN',
      profile: this.profile,
      time: new Date().toISOString(),
    }

    if (typeof resource.KmsKeyId === 'string') {
      /** if there is a key it should be encrypted, if not, something unexpected is going on */
      assert(
        resource.StorageEncrypted === true,
        'key found, but rds instance is not encrypted'
      )
      audit.state = await this.isKeyTrusted(
        resource.KmsKeyId,
        this.keyType,
        region
      )
    } else {
      audit.state = 'FAIL'
    }

    this.audits.push(audit)
  }

  scan = async ({ resource, region }: { resource: string; region: string }) => {
    let instances
    if (resource) {
      instances = await this.listDBInstances(region, resource)
    } else {
      instances = await this.listDBInstances(region)
    }

    for (const instance of instances) {
      assert(instance.DBInstanceArn, 'instances must have a ARN')
      await this.audit({
        resource: instance,
        region,
      })
    }
  }
}

export const handler = async (args: InstanceEncryptedInterface) => {
  const scanner = new PublicInstance({
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
