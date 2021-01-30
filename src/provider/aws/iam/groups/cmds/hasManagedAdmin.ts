/** TODO: this needs to support resource */

import {
  AWSScannerInterface,
  AuditResultInterface,
} from '@lstatro/cloud-search'
import { AttachedPolicy, Group } from 'aws-sdk/clients/iam'

import { AWS } from '../../../../../lib/aws/AWS'

const rule = 'HasManagedAdmin'

export const command = `${rule} [args]`

export const desc = `User groups should not have the AWS managed administrator 
policy directly attached. It is important to understand that only checks user
groups. A user could still have admin via an inline or a directly attached
policy. 

  OK      - Group does not have AdministratorAccess policy attached 
  UNKNOWN - Unable to determine if the group has AdministratorAccess attached 
  FAIL    - Group has AdministratorAccess policy attached

  note: This rule does not check inline policy.  It is still possible that a 
        group has administrator rights if they were applied via a inline policy. 

  note: This rule does not check direct user policy.  It is still possible the 
        user has admin directly attached.

`

export class HasManagedAdmin extends AWS {
  audits: AuditResultInterface[] = []
  service = 'iam'
  global = true

  constructor(public params: AWSScannerInterface) {
    super({ ...params, rule })
  }

  async audit({ resource }: { resource: string }) {
    const audit = this.getDefaultAuditObj({
      resource: resource,
      region: this.region,
    })

    const options = this.getOptions()

    const promise = new this.AWS.IAM(options)
      .listAttachedGroupPolicies({
        GroupName: resource,
      })
      .promise()

    const policies = await this.pager<AttachedPolicy>(
      promise,
      'AttachedPolicies'
    )

    for (const policy of policies) {
      if (policy.PolicyName === 'AdministratorAccess') {
        audit.state = 'FAIL'
      }
    }

    if (audit.state === 'UNKNOWN') {
      audit.state = 'OK'
    }

    this.audits.push(audit)
  }

  scan = async ({ resource }: { resource: string }) => {
    if (resource) {
      await this.audit({ resource })
    } else {
      const options = this.getOptions()

      const promise = new this.AWS.IAM(options).listGroups().promise()
      const groups = await this.pager<Group>(promise, 'Groups')

      for (const group of groups) {
        await this.audit({ resource: group.GroupName })
      }
    }
  }
}

export const handler = async (args: AWSScannerInterface) => {
  const scanner = new HasManagedAdmin(args)

  await scanner.start()
  scanner.output()
  return scanner.audits
}
