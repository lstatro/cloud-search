import { IAM } from 'aws-sdk'
import { AuditResultInterface, AWSScannerInterface } from 'cloud-scan'
import assert from 'assert'
import AWS from '../../../../../lib/aws/AWS'
import { AccessKeyMetadata, User } from 'aws-sdk/clients/iam'
import { CommandBuilder } from 'yargs'

const rule = 'MaxKeyAge'

export const command = `${rule} [args]`
export const desc = 'Keys may not be older then so many days'
export const builder: CommandBuilder = {
  maxAge: {
    alias: 'm',
    describe: 'the maximum age a key may be before it evaluates to FAIL',
    type: 'number',
    default: 90,
  },
}

interface MaxKeyAgeInterface extends AWSScannerInterface {
  maxAge: number
}

export default class MaxKeyAge extends AWS {
  audits: AuditResultInterface[] = []
  service = 's3'
  global = true
  maxAge: number

  constructor(public params: MaxKeyAgeInterface) {
    super({
      profile: params.profile,
      resourceId: params.resourceId,
      domain: params.domain,
      region: params.region,
      rule,
    })
    this.maxAge = params.maxAge
  }

  async audit(user: User) {
    const iam = new IAM(this.options)

    let marker: string | undefined

    do {
      const listAccessKeys = await iam
        .listAccessKeys({
          UserName: user.UserName,
          Marker: marker,
        })
        .promise()
      marker = listAccessKeys.Marker

      if (listAccessKeys.AccessKeyMetadata) {
        for (const keyMetaData of listAccessKeys.AccessKeyMetadata) {
          this.validate(user, keyMetaData)
        }
      }
    } while (marker)
  }

  validate = (user: User, keyMetaData: AccessKeyMetadata) => {
    const id = `${user.UserName}:${keyMetaData.AccessKeyId}`
    const now = new Date()
    const auditObject: AuditResultInterface = {
      name: id,
      provider: 'aws',
      physicalId: id,
      service: this.service,
      rule: this.rule,
      region: this.region,
      state: 'UNKNOWN',
      profile: this.profile,
      time: now.toISOString(),
    }

    assert(keyMetaData.CreateDate, 'key does not have a creation date')
    const delta = now.getTime() - keyMetaData.CreateDate.getTime()

    const seconds = delta / 1000
    const hours = seconds / 3600
    const days = hours / 24

    if (days >= this.maxAge) {
      auditObject.state = 'FAIL'
    } else {
      auditObject.state = 'OK'
    }

    this.audits.push(auditObject)
  }

  scan = async () => {
    const iam = new IAM(this.options)

    const users: User[] = []

    let marker: string | undefined

    do {
      const listUsers = await iam
        .listUsers({
          Marker: marker,
        })
        .promise()

      marker = listUsers.Marker

      if (listUsers.Users) {
        for (const user of listUsers.Users) {
          users.push(user)
        }
      }
    } while (marker)

    for (const user of users) {
      await this.audit(user)
    }
  }
}

interface MaxKeyAgeCliInterface
  extends AWSScannerInterface,
    MaxKeyAgeInterface {}

export const handler = async (args: MaxKeyAgeCliInterface) => {
  const scanner = new MaxKeyAge({
    region: args.region,
    profile: args.profile,
    resourceId: args.resourceId,
    domain: args.domain,
    maxAge: args.maxAge,
  })
  await scanner.start()
  scanner.output()
}
