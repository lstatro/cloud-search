import {
  AuditResultInterface,
  AWSScannerInterface,
} from '@lstatro/cloud-search'
import { InternetGateway } from 'aws-sdk/clients/ec2'
import { AWS } from '../../../../../lib/aws/AWS'
import assert from 'assert'

const rule = 'IgwAttachedToVpc'

export const command = `${rule} [args]`
export const desc = `Verifies that all internet gateways owned by this account.
are detached Note, shared VPC's don't necessarily own the IGW so they may not 
show up in this scan.

  OK      - The IGW is not attached to a VPC
  UNKNOWN - Unable to determine if the IGW has an attachment
  FAIL    - The IGW is attached to a VPC

  resourceId - IGW ID (igw-xxxxxx)
  
`

export class IgwAttachedToVpc extends AWS {
  audits: AuditResultInterface[] = []
  service = 'ec2'

  constructor(public params: AWSScannerInterface) {
    super({ ...params, rule })
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

    const audit = this.getDefaultAuditObj({
      resource: resource.InternetGatewayId,
      region: region,
    })

    audit.state = suspect ? 'FAIL' : 'OK'

    this.audits.push(audit)
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

    const promise = new this.AWS.EC2(options)
      .describeInternetGateways({
        InternetGatewayIds: resourceId ? [resourceId] : undefined,
      })
      .promise()

    const igws = await this.pager<InternetGateway>(promise, 'InternetGateways')
    for (const igw of igws) {
      this.audit({ resource: igw, region })
    }
  }
}

export const handler = async (args: AWSScannerInterface) => {
  const scanner = await new IgwAttachedToVpc(args)
  await scanner.start()
  scanner.output()
  return scanner.audits
}
