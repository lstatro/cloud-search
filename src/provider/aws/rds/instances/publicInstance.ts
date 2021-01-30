/** TODO: can this be handled by iam.simulatePrincipalPolicy? */

import {
  AWSScannerInterface,
  AuditResultInterface,
} from '@lstatro/cloud-search'

import { AWS } from '../../../../lib/aws/AWS'
import { DBInstance } from 'aws-sdk/clients/rds'
import assert from 'assert'

const rule = 'PublicInstance'

export const command = `${rule} [args]`

export const desc = `RDS instances must not have the PubliclyAccessible flag set to true

  OK      - The RDS instance has PubliclyAccessible set to false
  UNKNOWN - Unable to verify the public state of the instance
  FAIL    - The RDS instance has PubliclyAccessible set to true, meaning it's public

  resource: RDS instance ARN

  note: this rule targets DB Instances not DB Cluster's (Aurora clusters).

`

export class PublicInstance extends AWS {
  audits: AuditResultInterface[] = []
  service = 'rds'
  global = false

  constructor(public params: AWSScannerInterface) {
    super({ ...params, rule })
  }

  async audit({
    publiclyAccessible,
    resource,
    region,
  }: {
    publiclyAccessible: boolean | undefined
    resource: string
    region: string
  }) {
    const audit = this.getDefaultAuditObj({ resource, region })

    if (publiclyAccessible === true) {
      audit.state = 'FAIL'
    } else if (publiclyAccessible === false) {
      audit.state = 'OK'
    }
    this.audits.push(audit)
  }

  scan = async ({ resource, region }: { resource: string; region: string }) => {
    let instances
    const options = this.getOptions()
    options.region = region

    if (resource) {
      const promise = new this.AWS.RDS(options)
        .describeDBInstances({
          DBInstanceIdentifier: resource,
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
        publiclyAccessible: instance.PubliclyAccessible,
        resource: instance.DBInstanceArn,
        region,
      })
    }
  }
}

export const handler = async (args: AWSScannerInterface) => {
  const scanner = new PublicInstance(args)

  await scanner.start()
  scanner.output()
  return scanner.audits
}
