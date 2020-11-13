import { FlowLog, Vpc } from 'aws-sdk/clients/ec2'
import {
  AuditResultInterface,
  AWSClientOptionsInterface,
  AWSScannerInterface,
} from 'cloud-search'
import { AWS } from '../../../../../lib/aws/AWS'
import assert from 'assert'

const rule = 'FlowlogsEnabled'

export const command = `${rule} [args]`

export const desc = `VPC Instances should have flowlogs enabled

  OK      - Flowlogs are enabled
  WARNING - Not sure what would be warning yet
  UNKNOWN - Unable to determine flowlogs are enabled
  FAIL    - Flowlogs are not enabled

  resourceId: VpcId

`

export default class FlowlogsEnabled extends AWS {
  audits: AuditResultInterface[] = []
  service = 'ec2'
  global = false

  constructor(public params: AWSScannerInterface) {
    super({ ...params, rule })
  }

  async audit({ resource, region }: { resource: string; region: string }) {
    const audit = this.getDefaultAuditObj({
      resource: resource,
      region,
    })
    audit.state = 'OK'
    this.audits.push(audit)
  }

  scan = async ({
    resourceId,
    region,
  }: {
    resourceId: string | undefined
    region: string
  }) => {
    const options = this.getOptions()
    options.region = region
    let flowlogs
    if (resourceId) {
      flowlogs = await this.getFlowLogs(flowlogs, options, resourceId)
      if (flowlogs.length > 0) {
        await this.audit({ resource: resourceId, region })
      } else {
        const audit = this.getDefaultAuditObj({
          resource: resourceId,
          region,
        })
        audit.state = 'FAIL'
        this.audits.push(audit)
      }
    } else {
      let promise = new this.AWS.EC2(options).describeVpcs().promise()
      const vpcs = await this.pager<Vpc>(promise, 'Vpcs')
      for (const vpc of vpcs) {
        resourceId = vpc.VpcId
        assert(resourceId, 'resourceId must exist')
        flowlogs = new this.AWS.EC2(options)
          .describeFlowLogs({
            Filter: [
              {
                Name: 'resource-id',
                Values: [resourceId],
              },
            ],
          })
          .promise()
        flowlogs = await this.pager<FlowLog>(flowlogs, 'FlowLogs')
        if (flowlogs.length > 0) {
          await this.audit({ resource: resourceId, region })
        } else {
          const audit = this.getDefaultAuditObj({
            resource: resourceId,
            region,
          })
          audit.state = 'FAIL'
          this.audits.push(audit)
        }
      }
    }
  }

  private async getFlowLogs(
    flowlogs: any,
    options: AWSClientOptionsInterface,
    resourceId: string
  ) {
    flowlogs = new this.AWS.EC2(options)
      .describeFlowLogs({
        Filter: [
          {
            Name: 'resource-id',
            Values: [resourceId],
          },
        ],
      })
      .promise()
    flowlogs = await this.pager<FlowLog>(flowlogs, 'FlowLogs')
    return flowlogs
  }
}

export const handler = async (args: AWSScannerInterface) => {
  const scanner = new FlowlogsEnabled(args)
  await scanner.start()
  scanner.output()
  return scanner.audits
}
