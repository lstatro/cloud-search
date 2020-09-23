import { EC2 } from 'aws-sdk'
import { AuditResultInterface } from 'cloud-scan'
import { Arguments } from 'yargs'
import getOptions from '../../../../../lib/aws/options'
import toTerminal from '../../../../../lib/toTerminal'
import getRegions from '../../../../../lib/aws/getRegions'
import { InternetGateway } from 'aws-sdk/clients/ec2'
import AWS from '../../../../../lib/aws/AWS'

const rule = 'igwAttachedToVpc'

export const command = `${rule} [args]`
export const desc = `Verifies that all internet gateways owned by this account.
are detached Note, shared VPC's don't necessarily own the IGW so they may not 
show up in this scan. 
`

export class Scanner extends AWS {
  audits: AuditResultInterface[] = []
  service = 'ec2'

  constructor(
    public region: string,
    public profile: string,
    public resourceId: string,
    public domain: string
  ) {
    super({ profile, rule, resourceId, domain, region })
  }

  async audit(igw: InternetGateway, region: string) {
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

  scan = async ({
    region,
    resourceId,
  }: {
    region: string
    resourceId?: string
  }) => {
    const options = getOptions(this.profile)
    options.region = region

    const ec2 = new EC2(options)

    let nextToken: string | undefined

    try {
      do {
        const describeInternetGateways = await ec2
          .describeInternetGateways({
            NextToken: nextToken,
            InternetGatewayIds: resourceId ? [resourceId] : undefined,
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
        physicalId: resourceId,
        service: this.service,
        rule,
        region: region,
        state: 'UNKNOWN',
        profile: this.profile,
        time: new Date().toISOString(),
      })
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
