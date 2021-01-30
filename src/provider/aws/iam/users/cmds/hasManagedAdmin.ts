import {
  AWSScannerInterface,
  AuditResultInterface,
} from '@lstatro/cloud-search'
import { AttachedPolicy, User } from 'aws-sdk/clients/iam'

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
      .listAttachedUserPolicies({
        UserName: resource,
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

      const promise = new this.AWS.IAM(options).listUsers().promise()
      const users = await this.pager<User>(promise, 'Users')

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
