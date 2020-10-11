/** TODO: this needs to support resourceId */

import { AuditResultInterface, AWSScannerInterface } from 'cloud-search'
import AWS from '../../../../../lib/aws/AWS'

const rule = 'PublicRole'

export const command = `${rule} [args]`

export const desc = `Roles must not allow * in trust policy principal

  OK      - Role does not allow * in the trust document principal
  UNKNOWN - unable view the trust policy
  FAIL    - Role allows * in the trust document principal

  note: iam is global, passing in a region won't change results

`

export default class PublicRole extends AWS {
  audits: AuditResultInterface[] = []
  service = 'iam'
  global = true

  constructor(public params: AWSScannerInterface) {
    super({
      profile: params.profile,
      resourceId: params.resourceId,
      region: params.region,
      rule,
    })
  }

  async audit(userName: string) {
    const iam = new this.AWS.IAM(this.options)
  }

  scan = async ({ resourceId }: { resourceId: string }) => {
    if (resourceId) {
      await this.audit(resourceId)
    } else {
      const users = await this.listRoles()

      for (const user of users) {
        await this.audit(user.UserName)
      }
    }
  }
}

export const handler = async (args: AWSScannerInterface) => {
  const scanner = new PublicRole({
    region: args.region,
    profile: args.profile,
    resourceId: args.resourceId,
  })

  await scanner.start()
  scanner.output()
  return scanner.audits
}
