import {
  AWSScannerInterface,
  AuditResultInterface,
} from '@lstatro/cloud-search'
import { LoadBalancer, LoadBalancerAttribute } from 'aws-sdk/clients/elbv2'

import { AWS } from '../../../../../lib/aws/AWS'
import assert from 'assert'

export type LoadBalancerType = 'application' | 'network'

export interface Elbv2AccessLogsEnabledInterface extends AWSScannerInterface {
  type: LoadBalancerType
  rule: 'AlbAccessLogsEnabled' | 'NlbAccessLogsEnabled'
}

export class Elbv2AccessLogsEnabled extends AWS {
  audits: AuditResultInterface[] = []
  service = 'ec2'
  type: LoadBalancerType

  constructor(public params: Elbv2AccessLogsEnabledInterface) {
    super({ ...params })
    this.type = params.type
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
    resource,
  }: {
    region: string
    resource?: string
  }) => {
    const options = this.getOptions()
    options.region = region

    let promise

    if (resource) {
      promise = new this.AWS.ELBv2(options)
        .describeLoadBalancers({
          LoadBalancerArns: [resource],
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
      assert(this.type, 'loadbalancer type is required')
      if (loadbalancer.Type === this.type) {
        await this.audit({ resource: loadbalancer, region })
      }
    }
  }
}
