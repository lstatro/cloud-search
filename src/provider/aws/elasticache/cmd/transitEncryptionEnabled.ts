import { AuditResultInterface, AWSScannerInterface } from 'cloud-search'
import assert from 'assert'
import { AWS, keyTypeArg } from '../../../../lib/aws/AWS'
import { CacheCluster } from 'aws-sdk/clients/elasticache'

const rule = 'TransitEncryptionEnabled'

export const builder = {
  ...keyTypeArg,
}

export const command = `${rule} [args]`

export const desc = `Elasticache instances should enforce encryption in flight

  OK      - Elasticache cluster has transit encryption enabled
  UNKNOWN - Unable to determine if the elasticache cluster has transit encryption
  FAIL    - Elasticache cluster does not have encryption enabled

  resourceId: cluster, instance, or shard name

  note: Memcached instances do not support encryption therefore they'll always return FAIL
  note: Even standalone instances have a cluster ID

`

export default class TransitEncryptionEnabled extends AWS {
  audits: AuditResultInterface[] = []
  service = 'elasticache'
  global = false

  constructor(public params: AWSScannerInterface) {
    super({ ...params, rule })
  }

  async audit({
    resource,
    region,
  }: {
    resource: CacheCluster
    region: string
  }) {
    assert(resource.CacheClusterId, 'clusters must have a cluster ARN')
    const audit: AuditResultInterface = {
      provider: 'aws',
      physicalId: resource.CacheClusterId,
      service: this.service,
      rule: this.rule,
      region: region,
      state: 'UNKNOWN',
      profile: this.profile,
      time: new Date().toISOString(),
    }

    if (resource.TransitEncryptionEnabled) {
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
    resourceId: string
    region: string
  }) => {
    let clusters
    if (resourceId) {
      clusters = await this.listElastiCacheClusters(region, resourceId)
    } else {
      clusters = await this.listElastiCacheClusters(region)
    }

    for (const cluster of clusters) {
      await this.audit({
        resource: cluster,
        region,
      })
    }
  }
}

export const handler = async (args: AWSScannerInterface) => {
  const scanner = new TransitEncryptionEnabled(args)

  await scanner.start()
  scanner.output()
  return scanner.audits
}
