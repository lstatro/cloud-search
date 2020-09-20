import { EC2 } from 'aws-sdk'
import { AuditResultInterface, AWSClientOptionsInterface } from 'cloud-scan'
import { Arguments } from 'yargs'
import ora, { Ora } from 'ora'
import assert from 'assert'
import getOptions from '../../../../../lib/aws/options'
import toTerminal from '../../../../../lib/toTerminal'
import getRegions from '../../../../../lib/aws/getRegions'
import {
  DescribeSecurityGroupsResult,
  SecurityGroup,
} from 'aws-sdk/clients/ec2'

const rule = 'anyanyany'

export const command = `${rule} [args]`
export const desc =
  'search for security groups that allow any ip to access any range on any port'

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
        // await this.audit(this.resourceId)
      } else {
        await this.handleRegions()
      }
      this.spinner.succeed()
    } catch (err) {
      this.spinner.fail(err.message)
    }
  }

  audit = async (group: SecurityGroup) => {
    let suspect: boolean
    if (group.IpPermissions) {
      for (const permission of group.IpPermissions) {
        if (permission.IpProtocol === '-1') {
          if (permission.IpRanges) {
            for (const range of permission.IpRanges) {
              if (range.CidrIp === '0.0.0.0/0') {
                suspect = true
              }
            }
          }
        }
      }
    }
  }

  validate = (sgId: string) => {
    const auditObject: AuditResultInterface = {
      name: sgId,
      provider: 'aws',
      physicalId: sgId,
      service: this.service,
      rule,
      region: this.region,
      state: 'UNKNOWN',
      profile: this.profile,
      time: new Date().toISOString(),
    }

    this.audits.push(auditObject)
  }

  scan = async (region: string) => {
    const options = getOptions(this.profile)
    options.region = region

    const ec2 = new EC2(options)

    let nextToken: string | undefined

    do {
      const describeSecurityGroups = await ec2
        .describeSecurityGroups({
          NextToken: nextToken,
        })
        .promise()
      nextToken = describeSecurityGroups.NextToken
      if (describeSecurityGroups.SecurityGroups) {
        for (const group of describeSecurityGroups.SecurityGroups) {
          this.audit(group)
        }
      }
    } while (nextToken)
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
