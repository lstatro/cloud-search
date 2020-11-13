import { AuditResultInterface, AWSScannerInterface } from 'cloud-search'
import { AWS } from '../../../../../lib/aws/AWS'
import { LoadBalancer } from 'aws-sdk/clients/elbv2'
import assert from 'assert'
import { WebACLSummary } from 'aws-sdk/clients/wafregional'
import { WebACLSummary as WebACLSummaryV2 } from 'aws-sdk/clients/wafv2'

const rule = 'AlbWafEnabled'

export const command = `${rule} [args]`
export const desc = `Verifies application load balancers has an attached v2 WAF 
enabled

  OK      - LB has logging enabled
  WARNING - LB has logging enabled but does not have a target s3 bucket
  UNKNOWN - Unable to determine if LB has logging enabled
  FAIL    - LB does not have logging enabled

  resourceId - load balancer name

`

export class AlbWafEnabled extends AWS {
  audits: AuditResultInterface[] = []
  service = 'ec2'

  constructor(public params: AWSScannerInterface) {
    super({ ...params, rule })
  }

  async audit({
    resource,
    region,
    acls,
  }: {
    resource: LoadBalancer
    region: string
    acls: (WebACLSummary | WebACLSummaryV2)[]
  }) {
    assert(resource.LoadBalancerArn, 'load balancer must have a arn')

    console.log(JSON.stringify({ acls }, null, 2))

    const audit = this.getDefaultAuditObj({
      resource: resource.LoadBalancerArn,
      region: region,
    })

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

    // WebACLId: ResourceId;
    await new this.AWS.WAFRegional().listResourcesForWebACL().promise()

    // WebACLArn: ResourceArn;
    await new this.AWS.WAFV2().listResourcesForWebACL().promise()

    let acls: (WebACLSummary | WebACLSummaryV2)[]

    promise = new this.AWS.WAFV2(options)
      .listWebACLs({ Scope: 'REGIONAL' })
      .promise()
    const aclsV2 = await this.pager<WebACLSummaryV2>(promise, 'WebACLs')

    promise = new this.AWS.WAFRegional(options).listWebACLs().promise()
    acls = await this.pager<WebACLSummary>(promise, 'WebACLs')

    acls = acls.concat(aclsV2)

    for (const loadbalancer of loadBalancers) {
      await this.audit({ resource: loadbalancer, region, acls })
    }
  }
}

export const handler = async (args: AWSScannerInterface) => {
  const scanner = await new AlbWafEnabled(args)
  await scanner.start()
  scanner.output()
  return scanner.audits
}
