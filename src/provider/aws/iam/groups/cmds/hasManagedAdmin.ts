/** TODO: this needs to support resource */

import { AuditResultInterface, AWSScannerInterface } from 'cloud-search'
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

export default class HasManagedAdmin extends AWS {
  audits: AuditResultInterface[] = []
  service = 'iam'
  global = true

  constructor(public params: AWSScannerInterface) {
    super({ ...params, rule })
  }

  async audit({ resource }: { resource: string }) {
    const now = new Date()

    const audit: AuditResultInterface = {
      provider: 'aws',
      physicalId: resource,
      service: this.service,
      rule: this.rule,
      region: this.region,
      state: 'UNKNOWN',
      profile: this.profile,
      time: now.toISOString(),
    }

    const policies = await this.listAttachedGroupPolicies(resource)

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

  scan = async ({ resourceId }: { resourceId: string }) => {
    if (resourceId) {
      await this.audit({ resource: resourceId })
    } else {
      const groups = await this.listGroups()

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