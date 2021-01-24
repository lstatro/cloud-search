import { AWS } from '../../../../../lib/aws/AWS'
import { User } from 'aws-sdk/clients/iam'

const rule = 'UserMfaEnabled'

export const command = `${rule} [args]`

export const desc = `Users must have MFA enabled

  OK      - User has MFA enabled
  FAIL    - User does not have MFA enabled

`

export class UserMfaEnabled extends AWS {
  audits: AuditResultInterface[] = []
  service = 'iam'
  global = true

  constructor(public params: AWSScannerInterface) {
    super({ ...params, rule })
  }

  async audit({ resource }: { resource: string }) {
    const options = this.getOptions()

    const audit = this.getDefaultAuditObj({
      resource,
      region: this.region,
    })

    const listMFADevices = await new this.AWS.IAM(options)
      .listMFADevices({
        UserName: resource,
      })
      .promise()

    if (listMFADevices.MFADevices.length > 0) {
      audit.state = 'OK'
    } else {
      audit.state = 'FAIL'
    }

    this.audits.push(audit)
  }

  scan = async ({ resourceId }: { resourceId: string }) => {
    if (resourceId) {
      await this.audit({ resource: resourceId })
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
  const scanner = new UserMfaEnabled(args)

  await scanner.start()
  scanner.output()
  return scanner.audits
}
