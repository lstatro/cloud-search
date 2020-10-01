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

  OK      - the vpc does not have an IGW attached
  UNKNOWN - unable to determine if the VPC has an IGW attached
  FAIL    - the vpc has an IGW attached

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
    const igws = await this.describeInternetGateways(region, resourceId)
    for (const igw of igws) {
      this.audit(igw, region)
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
