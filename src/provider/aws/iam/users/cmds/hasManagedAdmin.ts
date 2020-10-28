import { AuditResultInterface, AWSScannerInterface } from 'cloud-search'
import { AWS } from '../../../../../lib/aws/AWS'

const rule = 'HasManagedAdmin'

export const command = `${rule} [args]`

export const desc = `Users should not have the AWS managed administrator policy 
directly applied to the user's permissions. It is important to understand 
that this rule only checks users to see if the AdministratorAccess managed 
policy is directly attached.  A user could still have admin via an inline or 
group policy. 

  OK      - User does not have AdministratorAccess policy directly attached 
  UNKNOWN - Unable to determine if the user has AdministratorAccess directly attached 
  FAIL    - User has AdministratorAccess policy directly attached

  note: this rule does not check inline policy.  It is still possible that a user has administrator rights if they
        were applied via a inline policy. 

  note: this rule does not check group policy.  It is still possible the user is in a group that has admin attached

`

export default class HasManagedAdmin extends AWS {
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

    const policies = await this.listAttachedUserPolicies(resource)

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
      const users = await this.listUsers()

      for (const user of users) {
        await this.audit({ resource: user.UserName })
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
