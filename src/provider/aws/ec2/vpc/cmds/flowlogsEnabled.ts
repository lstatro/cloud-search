import { FlowLog, Vpc } from 'aws-sdk/clients/ec2'
import { AuditResultInterface, AWSScannerInterface } from 'cloud-search'
import { AWS } from '../../../../../lib/aws/AWS'
import assert from 'assert'
import { option } from 'yargs'

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
    console.log('yehhh', resource, region)
    const audit = this.getDefaultAuditObj({
      resource: resource,
      region,
    })
    audit.state = 'OK'
    this.audits.push(audit)
  }

  scan = async ({ resource, region }: { resource: string; region: string }) => {
    const options = this.getOptions()
    options.region = region
    let flowlogs
    let params = {}
    let promise
    if (resource) {
      params = {
        Filter: [
          {
            Name: 'resource-id',
            Values: [resource],
          },
        ],
      }
      promise = new this.AWS.EC2(options).describeFlowLogs(params).promise()
      flowlogs = await this.pager<FlowLog>(promise, 'FlowLogs')
      for (const flowlog of flowlogs) {
        console.log('this is flowLog ...', flowlog)
        assert(
          flowlog.ResourceId,
          'The flowlog returned here should have a VpcId'
        )
        await this.audit({ resource: flowlog.ResourceId, region })
      }
    } else {
      promise = new this.AWS.EC2(options).describeVpcs().promise()
      const vpcs = await this.pager<Vpc>(promise, 'Vpcs')
      for (const vpc of vpcs) {
        params = {
          Filter: [
            {
              Name: 'resource-id',
              Values: [vpc.VpcId],
            },
          ],
        }
        flowlogs = await new this.AWS.EC2(options)
          .describeFlowLogs(params)
          .promise()
        console.log('these are flowlogs ...', flowlogs)
        console.log('flow logs', flowlogs)
      }
    }
  }
}

export const handler = async (args: AWSScannerInterface) => {
  const scanner = new FlowlogsEnabled(args)
  await scanner.start()
  scanner.output()
  return scanner.audits
}
