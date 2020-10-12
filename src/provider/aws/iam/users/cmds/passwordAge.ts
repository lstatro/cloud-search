/** TODO: this needs to support resourceId */

import { AuditResultInterface, AWSScannerInterface } from 'cloud-search'
import AWS from '../../../../../lib/aws/AWS'
import { CommandBuilder } from 'yargs'
import { assert } from 'console'

const rule = 'PasswordAge'

export const command = `${rule} [args]`
export const builder: CommandBuilder = {
  maxAge: {
    alias: 'm',
    describe: 'the maximum age a password may be before it evaluates to FAIL',
    type: 'number',
    default: 90,
  },
}
export const desc = `Passwords may not be older then so many days

  OK      - Password within expiration window
  UNKNOWN - unable to determine password age
  FAIL    - Password outside of expiration window

  note: iam is global, passing in a region won't change results

`

interface MaxPasswordAgeInterface extends AWSScannerInterface {
  maxAge: number
}

export default class PasswordAge extends AWS {
  audits: AuditResultInterface[] = []
  service = 'iam'
  global = true
  maxAge: number

  constructor(public params: MaxPasswordAgeInterface) {
    super({
      profile: params.profile,
      resourceId: params.resourceId,
      region: params.region,
      rule,
    })
    this.maxAge = params.maxAge
  }

  async audit(userName: string) {
    const iam = new this.AWS.IAM(this.options)
    let createDate
    try {
      const getLoginProfile = await iam
        .getLoginProfile({
          UserName: userName,
        })
        .promise()

      if (getLoginProfile.LoginProfile) {
        createDate = getLoginProfile.LoginProfile.CreateDate
      }
    } catch (err) {
      assert(err.code === 'NoSuchEntity', err)
    }

    this.validate(userName, createDate)
  }

  validate = (userName: string, createDate?: Date) => {
    const now = new Date()

    const auditObject: AuditResultInterface = {
      name: userName,
      provider: 'aws',
      physicalId: userName,
      service: this.service,
      rule: this.rule,
      region: this.region,
      state: 'UNKNOWN',
      profile: this.profile,
      time: now.toISOString(),
    }

    if (createDate) {
      const delta = now.getTime() - createDate.getTime()

      const seconds = delta / 1000
      const hours = seconds / 3600
      const days = hours / 24

      if (days >= this.maxAge) {
        auditObject.state = 'FAIL'
      } else {
        auditObject.state = 'OK'
      }
    } else {
      auditObject.state = 'OK'
      auditObject.comment = 'user does not have a password'
    }

    this.audits.push(auditObject)
  }

  scan = async ({ resourceId }: { resourceId: string }) => {
    if (resourceId) {
      await this.audit(resourceId)
    } else {
      const users = await this.listUsers()

      for (const user of users) {
        await this.audit(user.UserName)
      }
    }
  }
}

export interface MaxKeyAgeCliInterface
  extends AWSScannerInterface,
    MaxPasswordAgeInterface {}

export const handler = async (args: MaxKeyAgeCliInterface) => {
  const scanner = new PasswordAge({
    region: args.region,
    profile: args.profile,
    resourceId: args.resourceId,
    maxAge: args.maxAge,
  })

  await scanner.start()
  scanner.output()
  return scanner.audits
}
