import { EC2 } from 'aws-sdk'
import { AuditResultInterface, AWSClientOptionsInterface } from 'cloud-scan'
import { Arguments } from 'yargs'
import ora, { Ora } from 'ora'
import getOptions from '../../../../../lib/aws/options'
import toTerminal from '../../../../../lib/toTerminal'
import getRegions from '../../../../../lib/aws/getRegions'
import { SecurityGroup } from 'aws-sdk/clients/ec2'
import { assert } from 'console'

const rule = 'publicPermission'

export const command = `${rule} [args]`
export const desc =
  'search groups for v4/v6 public access permissions on any port'

export class Scanner {
  options: AWSClientOptionsInterface
  audits: AuditResultInterface[] = []
  service = 'ec2'
  spinner: Ora

  constructor(
    public region: string,
    public profile: string,
    public resourceId: string,
    public domain: string
  ) {
    this.options = getOptions(profile)
    this.spinner = ora({
      prefixText: rule,
    })
  }

  start = async () => {
    try {
      this.spinner.start()
      if (this.resourceId) {
        assert(
          this.region !== 'all',
          'must provide the resources specific region'
        )
        await this.scan(this.region, this.resourceId)
      } else {
        await this.handleRegions()
      }
      this.spinner.succeed()
    } catch (err) {
      this.spinner.fail(err.message)
    }
  }

  audit = async (group: SecurityGroup, region: string) => {
    let suspect
    /** does the security group have any inbound permissions? */
    if (group.IpPermissions) {
      /** for each permission in the group lets look for something bad */
      for (const permission of group.IpPermissions) {
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
      name: group.GroupName,
      provider: 'aws',
      physicalId: group.GroupId,
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

  scan = async (region: string, groupId?: string) => {
    const options = getOptions(this.profile)
    options.region = region

    const ec2 = new EC2(options)

    let nextToken: string | undefined

    /**
     * try to search for the group, if we find it neat,
     * if we don't return an unknown state object
     */
    try {
      do {
        const describeSecurityGroups = await ec2
          .describeSecurityGroups({
            NextToken: nextToken,
            /**
             * ew, listen- did we pass in a group, yea? well then lets filter
             * for only that.  No? then lets leave this undefined
             */
            GroupIds: groupId ? [groupId] : undefined,
          })
          .promise()
        nextToken = describeSecurityGroups.NextToken
        if (describeSecurityGroups.SecurityGroups) {
          for (const group of describeSecurityGroups.SecurityGroups) {
            this.audit(group, region)
          }
        }
      } while (nextToken)
    } catch (err) {
      const errs = ['InvalidGroup.NotFound', 'InvalidGroupId.Malformed']
      if (errs.includes(err.code)) {
        this.audits.push({
          provider: 'aws',
          comment: `unable to audit resource ${err.code} - ${err.message}`,
          physicalId: groupId,
          service: this.service,
          rule,
          region: region,
          state: 'UNKNOWN',
          profile: this.profile,
          time: new Date().toISOString(),
        })
      } else {
        throw err
      }
    }
  }

  handleRegions = async () => {
    const regions = await getRegions(this.region, this.profile, this.domain)

    for (const region of regions) {
      this.spinner.text = region
      await this.scan(region)
    }
  }
}

export const handler = async (args: Arguments) => {
  const { region, profile, resourceId, domain } = args
  const scanner = await new Scanner(
    region as string,
    profile as string,
    resourceId as string,
    domain as string
  )
  await scanner.start()
  toTerminal(scanner.audits)
}
