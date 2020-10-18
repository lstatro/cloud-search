import { AuditResultInterface, AWSScannerInterface } from 'cloud-search'
import { InternetGateway } from 'aws-sdk/clients/ec2'
import AWS from '../../../../../lib/aws/AWS'
import assert from 'assert'

const rule = 'IgwAttachedToVpc'

export const command = `${rule} [args]`
export const desc = `Verifies that all internet gateways owned by this account.
are detached Note, shared VPC's don't necessarily own the IGW so they may not 
show up in this scan.

  OK      - the IGW is not attached to a VPC
  UNKNOWN - unable to determine if the IGW has an attachment
  FAIL    - the IGW is attached to a VPC

  resourceId - IGW ID (igw-xxxxxx)
  
`

export default class IgwAttachedToVpc extends AWS {
  audits: AuditResultInterface[] = []
  service = 'ec2'

  constructor(public params: AWSScannerInterface) {
    super({
      profile: params.profile,
      resourceId: params.resourceId,
      region: params.region,
      verbosity: params.verbosity,
      rule,
    })
  }

  async audit({
    resource,
    region,
  }: {
    resource: InternetGateway
    region: string
  }) {
    assert(resource.InternetGatewayId, 'gateway does not have an IGW id')
    let suspect = false

    if (resource.Attachments) {
      for (const attachment of resource.Attachments) {
        if (attachment.State) {
          const states = ['available', 'attaching', 'attached', 'detaching']
          if (states.includes(attachment.State)) {
            suspect = true
          }
        }
      }
    }

    this.audits.push({
      provider: 'aws',
      physicalId: resource.InternetGatewayId,
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
      this.audit({ resource: igw, region })
    }
  }
}

export const handler = async (args: AWSScannerInterface) => {
  const scanner = await new IgwAttachedToVpc({
    region: args.region,
    profile: args.profile,
    resourceId: args.resourceId,
    verbosity: args.verbosity,
  })
  await scanner.start()
  scanner.output()
  return scanner.audits
}
