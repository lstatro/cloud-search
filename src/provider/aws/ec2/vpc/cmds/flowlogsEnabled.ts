import { AWS } from '../../../../../lib/aws/AWS'
import { Vpc } from 'aws-sdk/clients/ec2'
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

    try {
      const flowlogs = await this.getFlowLogs(options, resource)

      assert(flowlogs.FlowLogs)

      if (flowlogs.FlowLogs.length > 0) {
        audit.state = 'OK'
      } else {
        audit.state = 'FAIL'
      }
    } catch (error) {
      /**
       * This check should return state of UNKNOWN if we pop the assert.
       * This is because we are not confident in the state of resource
       */
    }
    this.audits.push(audit)
  }

  scan = async ({
    resourceId,
    region,
  }: {
    resourceId?: string
    region: string
  }) => {
    const options = this.getOptions()
    options.region = region
    if (resourceId) {
      await this.audit({ resource: resourceId, region })
    } else {
      const promise = new this.AWS.EC2(options).describeVpcs().promise()
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
    const flowlogs = await new this.AWS.EC2(options)
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
