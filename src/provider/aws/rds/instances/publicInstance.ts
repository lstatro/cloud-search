/** TODO: can this be handled by iam.simulatePrincipalPolicy? */

import { AuditResultInterface, AWSScannerInterface } from 'cloud-search'
import assert from 'assert'
import { AWS } from '../../../../lib/aws/AWS'

const rule = 'PublicInstance'

export const command = `${rule} [args]`

export const desc = `RDS instances must not have the PubliclyAccessible flag set to true

  OK      - the RDS instance has PubliclyAccessible set to false
  UNKNOWN - unable to verify the public state of the instance
  FAIL    - the RDS instance has PubliclyAccessible set to true, meaning it's public

  resourceId: RDS instance ARN

  note: this rule targets DB Instances not DB Cluster's (Aurora clusters).

`

export default class PublicInstance extends AWS {
  audits: AuditResultInterface[] = []
  service = 'rds'
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

  async audit({
    publiclyAccessible,
    resource,
    region,
  }: {
    publiclyAccessible: boolean | undefined
    resource: string
    region: string
  }) {
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
    if (publiclyAccessible === true) {
      audit.state = 'FAIL'
    } else if (publiclyAccessible === false) {
      audit.state = 'OK'
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
    if (resourceId) {
      instances = await this.listDBInstances(region, resourceId)
    } else {
      instances = await this.listDBInstances(region)
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
  const scanner = new PublicInstance({
    region: args.region,
    profile: args.profile,
    resourceId: args.resourceId,
    verbosity: args.verbosity,
  })

  await scanner.start()
  scanner.output()
  return scanner.audits
}
