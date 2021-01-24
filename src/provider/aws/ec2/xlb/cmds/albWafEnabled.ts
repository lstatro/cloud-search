import { AWS } from '../../../../../lib/aws/AWS'
import { LoadBalancer } from 'aws-sdk/clients/elbv2'
import { WebACLSummary } from 'aws-sdk/clients/wafregional'
import { WebACLSummary as WebACLSummaryV2 } from 'aws-sdk/clients/wafv2'
import assert from 'assert'

const rule = 'AlbWafEnabled'

export const command = `${rule} [args]`
export const desc = `Verifies application load balancers has an attached 
regional WAF (v2 or classic) 

  OK      - LB has a WAF attached
  FAIL    - LB does not have a WAF attached

  resourceId - load balancer ARN

`

export type AclsType = (WebACLSummary | WebACLSummaryV2)[]

export class AlbWafEnabled extends AWS {
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

    const audit = this.getDefaultAuditObj({
      resource: resource.LoadBalancerArn,
      region: region,
    })

    const getWebACLForResource = await new this.AWS.WAFV2(options)
      .getWebACLForResource({
        ResourceArn: resource.LoadBalancerArn,
      })
      .promise()

    /**
     * finding any v2 waf means this is compliant, but if we don't find anything
     * we should fail back to looking at regional WAFs, and if we find anything
     * there it is compliant.  If we don't find a v2 or regional waf it is
     * non-compliant
     */
    if (getWebACLForResource.WebACL) {
      audit.state = 'OK'
    } else {
      const getWebACLForResource = await new this.AWS.WAFRegional(options)
        .getWebACLForResource({
          ResourceArn: resource.LoadBalancerArn,
        })
        .promise()

      if (getWebACLForResource.WebACLSummary) {
        audit.state = 'OK'
      } else {
        audit.state = 'FAIL'
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
  const scanner = await new AlbWafEnabled(args)
  await scanner.start()
  scanner.output()
  return scanner.audits
}
