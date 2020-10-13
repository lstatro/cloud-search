import {
  AuditResultInterface,
  AWSScannerCliArgsInterface,
  AWSScannerInterface,
} from 'cloud-search'
import { SecurityGroup } from 'aws-sdk/clients/ec2'
import AWS from '../../../../../lib/aws/AWS'

const rule = 'PublicPermission'

export const command = `${rule} [args]`
export const desc = `searches security groups for 0.0.0.0/0 or ::/0 on any port

  OK      - the group does not contain 0.0.0.0/0 or ::/0 ingress permissions
  UNKNOWN - unable to determine if the group includes 0.0.0.0/0 or ::/0
  FAIL    - the group allows 0.0.0.0/0 or ::/0 ingress

  resourceId - security group id (sg-xxxxxx)

`

export default class PublicPermission extends AWS {
  audits: AuditResultInterface[] = []
  service = 'ec2'

  constructor(public params: AWSScannerInterface) {
    super({
      profile: params.profile,
      resourceId: params.resourceId,
      region: params.region,
      rule,
    })
  }

  audit = async ({
    resourceId,
    region,
  }: {
    resourceId: SecurityGroup
    region: string
  }) => {
    let suspect
    /** does the security group have any inbound permissions? */
    if (resourceId.IpPermissions) {
      /** for each permission in the group lets look for something bad */
      for (const permission of resourceId.IpPermissions) {
        /** are there any ranges */
        if (permission.IpRanges) {
          /** we need to inspect each range in the group */
          for (const range of permission.IpRanges) {
            /** is that range quad zeros?  (allow the internet) */
            if (range.CidrIp === '0.0.0.0/0') {
              /** okay this guy is sketchy */
              suspect = true
            }
          }
        }
        /** are there any v6 ranges with this group? */
        if (permission.Ipv6Ranges) {
          /** we need to inspect each v6 range in the group */
          for (const range of permission.Ipv6Ranges) {
            /** is this range the v6 version of quad zeros? */
            if (range.CidrIpv6 === '::/0') {
              /** sketch level 100 */
              suspect = true
            }
          }
        }
      }
    }
    this.audits.push({
      name: resourceId.GroupName,
      provider: 'aws',
      physicalId: resourceId.GroupId,
      service: this.service,
      rule,
      region: region,
      /**
       * ew ternary- did we find something sketchy when reviewing the group?
       * - yea? FAIL!  this is crap, we should seek out an adult
       * - nah bro (or broette), we OK
       */
      state: suspect ? 'FAIL' : 'OK',
      profile: this.profile,
      time: new Date().toISOString(),
    })
  }

  scan = async ({
    region,
    resourceId,
  }: {
    region: string
    resourceId?: string
  }) => {
    const groups = await this.describeSecurityGroups(region, resourceId)
    for (const group of groups) {
      await this.audit({ resourceId: group, region })
    }
  }
}

export const handler = async (args: AWSScannerCliArgsInterface) => {
  const scanner = await new PublicPermission({
    region: args.region,
    profile: args.profile,
    resourceId: args.resourceId,
  })
  await scanner.start()
  scanner.output()
  return scanner.audits
}
