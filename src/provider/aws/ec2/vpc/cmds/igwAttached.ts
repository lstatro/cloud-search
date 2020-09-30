import {
  AuditResultInterface,
  AWSScannerCliArgsInterface,
  AWSScannerInterface,
} from 'cloud-search'
import { InternetGateway } from 'aws-sdk/clients/ec2'
import AWS from '../../../../../lib/aws/AWS'

const rule = 'IgwAttachedToVpc'

export const command = `${rule} [args]`
export const desc = `Verifies that all internet gateways owned by this account.
are detached Note, shared VPC's don't necessarily own the IGW so they may not 
show up in this scan. 
`

export default class IgwAttachedToVpc extends AWS {
  audits: AuditResultInterface[] = []
  service = 'ec2'

  constructor(public params: AWSScannerInterface) {
    super({
      profile: params.profile,
      resourceId: params.resourceId,
      domain: params.domain,
      region: params.region,
      rule,
    })
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
    const options = this.getOptions()
    options.region = region

    const ec2 = new this.AWS.EC2(options)

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
        } else {
          this.spinner.text = 'no internet gateways found'
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

export const handler = async (args: AWSScannerCliArgsInterface) => {
  const scanner = await new IgwAttachedToVpc({
    region: args.region,
    profile: args.profile,
    resourceId: args.resourceId,
    domain: args.domain,
  })
  await scanner.start()
  scanner.output()
  return scanner.audits
}
