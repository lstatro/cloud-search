import { AWS } from '../../../../../lib/aws/AWS'
import { LoadBalancerDescription } from 'aws-sdk/clients/elb'
import assert from 'assert'

const rule = 'ElbDesyncMode'

export const command = `${rule} [args]`
export const desc = `Verifies classic elastic load balancer's desync mode 
enabled

  OK      - LB is set to strict mode
  WARNING - LB is set to defensive mode
  UNKNOWN - Unable to determine LB'er desync mode
  FAIL    - LB is set to monitor or does not have the mode enabled

  resourceId - load balancer name

`

export class ElbDesyncMode extends AWS {
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

    let mode = 'monitor'

    if (attributes) {
      if (attributes.AdditionalAttributes) {
        for (const attribute of attributes.AdditionalAttributes) {
          if (attribute.Key) {
            if (attribute.Key.includes('desyncmitigationmode')) {
              if (attribute.Value) {
                mode = attribute.Value
              }
            }
          }
        }
      }
    }

    const modeMap: { [key: string]: 'OK' | 'WARNING' | 'FAIL' } = {
      strictest: 'OK',
      defensive: 'WARNING',
      monitor: 'FAIL',
    }

    if (modeMap[mode]) {
      audit.state = modeMap[mode]
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
  const scanner = await new ElbDesyncMode(args)
  await scanner.start()
  scanner.output()
  return scanner.audits
}
