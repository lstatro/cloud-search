import { EC2 } from 'aws-sdk'
import { AuditResultInterface, AWSClientOptionsInterface } from 'cloud-scan'
import { Arguments } from 'yargs'
import ora, { Ora } from 'ora'
import getOptions from '../../../../../lib/aws/options'
import toTerminal from '../../../../../lib/toTerminal'
import getRegions from '../../../../../lib/aws/getRegions'
import { InternetGateway } from 'aws-sdk/clients/ec2'
import { assert } from 'console'

const rule = 'igwAttachedToVpc'

export const command = `${rule} [args]`
export const desc = `Verifies that all internet gateways owned by this account.
are detached Note, shared VPC's don't necessarily own the IGW so they may not 
show up in this scan. 
`

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

  audit = async (igw: InternetGateway, region: string) => {
    let suspect = false

    if (igw.Attachments) {
      for (const attachment of igw.Attachments) {
        if (attachment.State) {
          const states = ['available', 'attaching', 'attached', 'detaching']
          if (states.includes(attachment.State)) {
            suspect = true
          }
        }
      }
    }

    this.audits.push({
      name: igw.InternetGatewayId,
      provider: 'aws',
      physicalId: igw.InternetGatewayId,
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

  scan = async (region: string, igwId?: string) => {
    const options = getOptions(this.profile)
    options.region = region

    const ec2 = new EC2(options)

    let nextToken: string | undefined

    try {
      do {
        const describeInternetGateways = await ec2
          .describeInternetGateways({
            NextToken: nextToken,
            InternetGatewayIds: igwId ? [igwId] : undefined,
          })
          .promise()

        nextToken = describeInternetGateways.NextToken

        if (describeInternetGateways.InternetGateways) {
          for (const igw of describeInternetGateways.InternetGateways) {
            this.audit(igw, region)
          }
        }
      } while (nextToken)
    } catch (err) {
      this.audits.push({
        provider: 'aws',
        comment: `unable to audit resource ${err.code} - ${err.message}`,
        physicalId: igwId,
        service: this.service,
        rule,
        region: region,
        state: 'UNKNOWN',
        profile: this.profile,
        time: new Date().toISOString(),
      })
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
