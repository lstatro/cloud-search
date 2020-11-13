import {
  AuditResultInterface,
  AWSScannerInterface,
} from '@lstatro/cloud-search'
import { AWS } from '../../../../../lib/aws/AWS'
import { CommandBuilder } from 'yargs'
import { assert } from 'console'
import { User } from 'aws-sdk/clients/iam'

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
  UNKNOWN - Unable to determine password age
  FAIL    - Password outside of expiration window

  note: iam is global, passing in a region won't change results

`

interface MaxPasswordAgeInterface extends AWSScannerInterface {
  maxAge: number
}

export class PasswordAge extends AWS {
  audits: AuditResultInterface[] = []
  service = 'iam'
  global = true
  maxAge: number

  constructor(public params: MaxPasswordAgeInterface) {
    super({ ...params, rule })
    this.maxAge = params.maxAge
  }

  async audit({ resource }: { resource: string }) {
    const options = this.getOptions()

    const iam = new this.AWS.IAM(options)
    let createDate
    try {
      const getLoginProfile = await iam
        .getLoginProfile({
          UserName: resource,
        })
        .promise()

      if (getLoginProfile.LoginProfile) {
        createDate = getLoginProfile.LoginProfile.CreateDate
      }
    } catch (err) {
      assert(err.code === 'NoSuchEntity', err)
    }

    this.validate(resource, createDate)
  }

  validate = (userName: string, createDate?: Date) => {
    const now = new Date()

    const audit = this.getDefaultAuditObj({
      resource: userName,
      region: this.region,
    })

    if (createDate) {
      const delta = now.getTime() - createDate.getTime()

      const seconds = delta / 1000
      const hours = seconds / 3600
      const days = hours / 24

      if (days >= this.maxAge) {
        audit.state = 'FAIL'
      } else {
        audit.state = 'OK'
      }
    } else {
      audit.state = 'OK'
      audit.comment = 'user does not have a password'
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

export interface MaxKeyAgeCliInterface
  extends AWSScannerInterface,
    MaxPasswordAgeInterface {}

export const handler = async (args: MaxKeyAgeCliInterface) => {
  const scanner = new PasswordAge(args)

  await scanner.start()
  scanner.output()
  return scanner.audits
}
