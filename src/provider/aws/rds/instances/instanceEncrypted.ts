import { AWS, keyTypeArg } from '../../../../lib/aws/AWS'

import { CommandBuilder } from 'yargs'
import { DBInstance } from 'aws-sdk/clients/rds'
import assert from 'assert'

const rule = 'InstanceEncrypted'

export const builder: CommandBuilder = {
  ...keyTypeArg,
}

export const command = `${rule} [args]`

export const desc = `RDS instances must have its storage encrypted at rest

  OK      - The RDS instance has its storage encrypted at rest
  WARNING - The RDS instance has its storage encrypted with the wrong key type
  UNKNOWN - Unable to verify the instance has its storage encrypted at rest
  FAIL    - The RDS instance does not have its storage encrypted at rest

  resourceId: DB instance identifier

  note: this rule targets DB Instances not DB Cluster's (Aurora clusters).

`

export class InstanceEncrypted extends AWS {
  audits: AuditResultInterface[] = []
  service = 'rds'
  global = false

  constructor(public params: AWSScannerInterface) {
    super({ ...params, rule })
    this.keyType = params.keyType
  }

  async audit({ resource, region }: { resource: DBInstance; region: string }) {
    assert(resource.DBInstanceArn, 'instance does not have an instance ARN')

    const audit = this.getDefaultAuditObj({
      resource: resource.DBInstanceArn,
      region,
    })

    if (typeof resource.KmsKeyId === 'string') {
      /** if there is a key it should be encrypted, if not, something unexpected is going on */
      assert(
        resource.StorageEncrypted === true,
        'key found, but rds instance is not encrypted'
      )
      assert(this.keyType, 'key type is required')
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

  scan = async ({
    resourceId,
    region,
  }: {
    resourceId: string
    region: string
  }) => {
    let instances

    const options = this.getOptions()
    options.region = region

    if (resourceId) {
      const promise = new this.AWS.RDS(options)
        .describeDBInstances({
          DBInstanceIdentifier: resourceId,
        })
        .promise()
      instances = await this.pager<DBInstance>(promise, 'DBInstances')
    } else {
      const promise = new this.AWS.RDS(options).describeDBInstances().promise()
      instances = await this.pager<DBInstance>(promise, 'DBInstances')
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

export const handler = async (args: AWSScannerInterface) => {
  const scanner = new InstanceEncrypted(args)

  await scanner.start()
  scanner.output()
  return scanner.audits
}
