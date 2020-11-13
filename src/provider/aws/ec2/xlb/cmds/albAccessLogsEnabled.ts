/**
 * TODO: xlb's likely cannot have logging enabled w/o a proper s3 bucket set
 *       at least, I haven't been able to force that setting via the cli.  We
 *       may want to consider just looking for the logging flag and leave the
 *       rest as implied.
 */

import {
  AuditResultInterface,
  AWSScannerInterface,
} from '@lstatro/cloud-search'
import { AWS } from '../../../../../lib/aws/AWS'
import assert from 'assert'
import { LoadBalancer, LoadBalancerAttribute } from 'aws-sdk/clients/elbv2'

const rule = 'AlbAccessLogsEnabled'

export const command = `${rule} [args]`
export const desc = `Verifies application load balancers has access logging 
enabled

  OK      - LB has logging enabled
  WARNING - LB has logging enabled but does not have a target s3 bucket
  UNKNOWN - Unable to determine if LB has logging enabled
  FAIL    - LB does not have logging enabled

  resourceId - load balancer name

`

export class AlbAccessLogsEnabled extends AWS {
  audits: AuditResultInterface[] = []
  service = 'ec2'

  constructor(public params: AWSScannerInterface) {
    super({ ...params, rule })
  }

  async audit({
    resource,
    region,
  }: {
    resource: LoadBalancer
    region: string
  }) {
    assert(resource.LoadBalancerArn, 'load balancer must have a arn')

    const options = this.getOptions()
    options.region = region

    const describeLoadBalancerAttributes = await new this.AWS.ELBv2(options)
      .describeLoadBalancerAttributes({
        LoadBalancerArn: resource.LoadBalancerArn,
      })
      .promise()

    const attributes = describeLoadBalancerAttributes.Attributes

    const audit = this.getDefaultAuditObj({
      resource: resource.LoadBalancerArn,
      region: region,
    })

    if (attributes) {
      const { isLogging, hasBucket } = this.parseAttributes(attributes)
      if (isLogging) {
        audit.state = 'WARNING'
        if (hasBucket) {
          audit.state = 'OK'
        }
      } else {
        audit.state = 'FAIL'
      }
    }

    this.audits.push(audit)
  }

  parseAttributes = (attributes: LoadBalancerAttribute[]) => {
    let isLogging = false
    let hasBucket = false

    for (const attribute of attributes) {
      if (attribute.Key === 'access_logs.s3.enabled') {
        if (attribute.Value === 'true') {
          isLogging = true
        }
      }
      if (attribute.Key === 'access_logs.s3.bucket') {
        /** if there is no bucket, it'll default to '' which should show as truthy false */
        if (attribute.Value) {
          hasBucket = true
        }
      }
    }
    return { isLogging, hasBucket }
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
      promise = new this.AWS.ELBv2(options)
        .describeLoadBalancers({
          LoadBalancerArns: [resourceId],
        })
        .promise()
    } else {
      promise = new this.AWS.ELBv2(options).describeLoadBalancers().promise()
    }

    const loadBalancers = await this.pager<LoadBalancer>(
      promise,
      'LoadBalancers'
    )

    for (const loadbalancer of loadBalancers) {
      await this.audit({ resource: loadbalancer, region })
    }
  }
}

export const handler = async (args: AWSScannerInterface) => {
  const scanner = await new AlbAccessLogsEnabled(args)
  await scanner.start()
  scanner.output()
  return scanner.audits
}
