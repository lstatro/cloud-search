import { Vpc } from 'aws-sdk/clients/ec2'
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
    const options = this.getOptions()
    options.region = region
    const audit = this.getDefaultAuditObj({
      resource: resource,
      region,
    })
    let flowlogs = await this.getFlowLogs(options, resource)

    assert(flowlogs.FlowLogs)
    if (flowlogs.FlowLogs.length > 0) {
      audit.state = 'OK'
    } else {
      audit.state = 'FAIL'
    }
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
    if (resourceId) {
      await this.audit({ resource: resourceId, region })
    } else {
      let promise = new this.AWS.EC2(options).describeVpcs().promise()
      const vpcs = await this.pager<Vpc>(promise, 'Vpcs')
      for (const vpc of vpcs) {
        assert(vpc.VpcId)
        await this.audit({ resource: vpc.VpcId, region })
      }
    }
  }

  private async getFlowLogs(
    options: AWSClientOptionsInterface,
    resourceId: string
  ) {
    let flowlogs = await new this.AWS.EC2(options)
      .describeFlowLogs({
        Filter: [
          {
            Name: 'resource-id',
            Values: [resourceId],
          },
        ],
      })
      .promise()
    return flowlogs
  }
}

export const handler = async (args: AWSScannerInterface) => {
  const scanner = new FlowlogsEnabled(args)
  await scanner.start()
  scanner.output()
  return scanner.audits
}
