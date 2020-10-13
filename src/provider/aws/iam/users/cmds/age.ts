/** TODO: this needs to support resourceId */

import { AuditResultInterface, AWSScannerInterface } from 'cloud-search'
import AWS from '../../../../../lib/aws/AWS'
import { AccessKeyMetadata, User } from 'aws-sdk/clients/iam'
import { CommandBuilder } from 'yargs'

const rule = 'MaxKeyAge'

export const command = `${rule} [args]`
export const builder: CommandBuilder = {
  maxAge: {
    alias: 'm',
    describe: 'the maximum age a key may be before it evaluates to FAIL',
    type: 'number',
    default: 90,
  },
}
export const desc = `Keys may not be older then so many days

  OK      - Keys are within the rotation period
  UNKNOWN - unable to determine the key's age
  FAIL    - they keys need rotation

  note: iam is global, passing in a region won't change results
  note: does not support single user requests (yet!)

`

interface MaxKeyAgeInterface extends AWSScannerInterface {
  maxAge: number
}

export default class MaxKeyAge extends AWS {
  audits: AuditResultInterface[] = []
  service = 'iam'
  global = true
  maxAge: number

  constructor(public params: MaxKeyAgeInterface) {
    super({
      profile: params.profile,
      resourceId: params.resourceId,
      region: params.region,
      rule,
    })
    this.maxAge = params.maxAge
  }

  async audit({ resourceId }: { resourceId: User }) {
    const iam = new this.AWS.IAM(this.options)

    let marker: string | undefined

    do {
      /** TODO: listAccessKeys needs to move into the AWS class */
      const listAccessKeys = await iam
        .listAccessKeys({
          UserName: resourceId.UserName,
          Marker: marker,
        })
        .promise()
      marker = listAccessKeys.Marker

      if (listAccessKeys.AccessKeyMetadata) {
        for (const keyMetaData of listAccessKeys.AccessKeyMetadata) {
          this.validate(resourceId, keyMetaData)
        }
      } else {
        this.validate(resourceId, {})
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

    if (keyMetaData.CreateDate) {
      const delta = now.getTime() - keyMetaData.CreateDate.getTime()

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
      auditObject.comment = 'no key metadata found'
    }

    this.audits.push(auditObject)
  }

  /** TODO: setup age to handle resource based requests
   *
   * it appears that we only need the user name, not the entire user object
   * we should therefore be able to cut it back to just the name string
   * (resourceId) and pass that into the audit and validate function to get
   * this functionality
   */
  scan = async () => {
    const users = await this.listUsers()

    for (const user of users) {
      await this.audit({ resourceId: user })
    }
  }
}

export interface MaxKeyAgeCliInterface
  extends AWSScannerInterface,
    MaxKeyAgeInterface {}

export const handler = async (args: MaxKeyAgeCliInterface) => {
  const scanner = new MaxKeyAge({
    region: args.region,
    profile: args.profile,
    resourceId: args.resourceId,
    maxAge: args.maxAge,
  })

  await scanner.start()
  scanner.output()
  return scanner.audits
}
