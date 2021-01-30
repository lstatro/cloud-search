import {
  AWSScannerInterface,
  AuditResultInterface,
} from '@lstatro/cloud-search'

import { AWS } from '../../../../../lib/aws/AWS'
import { SecurityGroup } from 'aws-sdk/clients/ec2'
import assert from 'assert'

const rule = 'PublicPermission'

export const command = `${rule} [args]`
export const desc = `searches security groups for 0.0.0.0/0 or ::/0 on any port

  OK      - The group does not contain 0.0.0.0/0 or ::/0 ingress permissions
  UNKNOWN - Unable to determine if the group includes 0.0.0.0/0 or ::/0
  FAIL    - The group allows 0.0.0.0/0 or ::/0 ingress

  resource - security group id (sg-xxxxxx)

`

export class PublicPermission extends AWS {
  audits: AuditResultInterface[] = []
  service = 'ec2'

  constructor(public params: AWSScannerInterface) {
    super({ ...params, rule })
  }

  audit = async ({
    resource,
    region,
  }: {
    resource: SecurityGroup
    region: string
  }) => {
    assert(resource.GroupId, 'security group does nto have a group id')
    let suspect
    /** does the security group have any inbound permissions? */
    if (resource.IpPermissions) {
      /** for each permission in the group lets look for something bad */
      for (const permission of resource.IpPermissions) {
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

    const audit = this.getDefaultAuditObj({
      resource: resource.GroupId,
      region: region,
    })

    audit.state = suspect ? 'FAIL' : 'OK'
    audit.name = resource.GroupName

    this.audits.push(audit)
  }

  scan = async ({
    region,
    resource,
  }: {
    region: string
    resource?: string
  }) => {
    const options = this.getOptions()
    options.region = region

    const promise = new this.AWS.EC2(options)
      .describeSecurityGroups({
        GroupIds: resource ? [resource] : undefined,
      })
      .promise()
    const groups = await this.pager<SecurityGroup>(promise, 'SecurityGroups')

    for (const group of groups) {
      await this.audit({ resource: group, region })
    }
  }
}

export const handler = async (args: AWSScannerInterface) => {
  const scanner = await new PublicPermission(args)
  await scanner.start()
  scanner.output()
  return scanner.audits
}
