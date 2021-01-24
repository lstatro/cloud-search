import { AWS } from '../../../../../lib/aws/AWS'
import { LoadBalancerDescription } from 'aws-sdk/clients/elb'
import assert from 'assert'

const rule = 'ElbAccessLogsEnabled'

export const command = `${rule} [args]`
export const desc = `Verifies classic elastic load balancers has access logging 
enabled

  OK      - LB has logging enabled
  WARNING - LB has logging enabled but does not have a target s3 bucket
  UNKNOWN - Unable to determine if LB has logging enabled
  FAIL    - LB does not have logging enabled

  resourceId - load balancer name

`

export class ElbAccessLogsEnabled extends AWS {
  audits: AuditResultInterface[] = []
  service = 'ec2'

  constructor(public params: AWSScannerInterface) {
    super({ ...params, rule })
  }

  async audit({
    resource,
    region,
  }: {
    resource: LoadBalancerDescription
    region: string
  }) {
    assert(resource.LoadBalancerName, 'load balancer must have a name')

    const options = this.getOptions()
    options.region = region

    const describeLoadBalancerAttributes = await new this.AWS.ELB(options)
      .describeLoadBalancerAttributes({
        LoadBalancerName: resource.LoadBalancerName,
      })
      .promise()

    const attributes = describeLoadBalancerAttributes.LoadBalancerAttributes

    const audit = this.getDefaultAuditObj({
      resource: resource.LoadBalancerName,
      region: region,
    })

    if (attributes) {
      if (attributes.AccessLog) {
        if (attributes.AccessLog.Enabled === true) {
          audit.state = 'WARNING'
          if (typeof attributes.AccessLog.S3BucketName === 'string') {
            audit.state = 'OK'
          }
        } else {
          audit.state = 'FAIL'
        }
      }
    }

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

    let promise

    if (resourceId) {
      promise = new this.AWS.ELB(options)
        .describeLoadBalancers({
          LoadBalancerNames: [resourceId],
        })
        .promise()
    } else {
      promise = new this.AWS.ELB(options).describeLoadBalancers().promise()
    }

    const loadBalancers = await this.pager<LoadBalancerDescription>(
      promise,
      'LoadBalancerDescriptions'
    )

    for (const loadbalancer of loadBalancers) {
      await this.audit({ resource: loadbalancer, region })
    }
  }
}

export const handler = async (args: AWSScannerInterface) => {
  const scanner = await new ElbAccessLogsEnabled(args)
  await scanner.start()
  scanner.output()
  return scanner.audits
}
