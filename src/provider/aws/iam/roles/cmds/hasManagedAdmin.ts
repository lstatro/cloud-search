import { AttachedPolicy, Role } from 'aws-sdk/clients/iam'
import {
  AuditResultInterface,
  AWSScannerInterface,
} from '@lstatro/cloud-search'
import { AWS } from '../../../../../lib/aws/AWS'

const rule = 'HasManagedAdmin'

export const command = `${rule} [args]`

export const desc = `Roles should not have the AWS managed administrator policy 
directly applied. It is important to understand that this rule only checks roles
to see if the AdministratorAccess managed policy is directly attached.  A role
could still have admin via an inline policy.

  OK      - Role does not have AdministratorAccess policy directly attached 
  UNKNOWN - Unable to determine if the role has AdministratorAccess directly attached 
  FAIL    - Role has AdministratorAccess policy directly attached

  note: this rule does not check inline policy.  It is still possible that a 
        role has administrator rights if they were applied via a inline policy. 

`

export class HasManagedAdmin extends AWS {
  audits: AuditResultInterface[] = []
  service = 'iam'
  global = true

  constructor(public params: AWSScannerInterface) {
    super({ ...params, rule })
  }

  async audit({ resource }: { resource: string }) {
    const audit = this.getDefaultAuditObj({ resource, region: this.region })

    const options = this.getOptions()

    const promise = new this.AWS.IAM(options)
      .listAttachedRolePolicies({
        RoleName: resource,
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

  scan = async ({ resourceId }: { resourceId: string }) => {
    if (resourceId) {
      await this.audit({ resource: resourceId })
    } else {
      const options = this.getOptions()

      const promise = new this.AWS.IAM(options).listRoles().promise()
      const roles = await this.pager<Role>(promise, 'Roles')

      for (const role of roles) {
        await this.audit({ resource: role.RoleName })
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
