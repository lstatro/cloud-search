import { AWS, keyTypeArg } from '../../../../lib/aws/AWS'
import {
  AWSScannerInterface,
  AuditResultInterface,
} from '@lstatro/cloud-search'

import { CacheCluster } from 'aws-sdk/clients/elasticache'
import assert from 'assert'

const rule = 'TransitEncryptionEnabled'

export const builder = {
  ...keyTypeArg,
}

export const command = `${rule} [args]`

export const desc = `Elasticache instances should enforce encryption in flight

  OK      - Elasticache cluster has transit encryption enabled
  UNKNOWN - Unable to determine if the elasticache cluster has transit encryption
  FAIL    - Elasticache cluster does not have encryption enabled

  resource: cluster, instance, or shard name

  note: Memcached instances do not support encryption therefore they'll always return FAIL
  note: Even standalone instances have a cluster ID

`

export class TransitEncryptionEnabled extends AWS {
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

    const audit = this.getDefaultAuditObj({
      resource: resource.CacheClusterId,
      region: region,
    })

    if (resource.TransitEncryptionEnabled) {
      audit.state = 'OK'
    } else {
      audit.state = 'FAIL'
    }

    this.audits.push(audit)
  }

  scan = async ({ resource, region }: { resource: string; region: string }) => {
    let clusters
    const options = this.getOptions()
    options.region = region

    if (resource) {
      const promise = new this.AWS.ElastiCache(options)
        .describeCacheClusters({
          CacheClusterId: resource,
        })
        .promise()
      clusters = await this.pager<CacheCluster>(promise, 'CacheClusters')
    } else {
      const promise = new this.AWS.ElastiCache(options)
        .describeCacheClusters()
        .promise()
      clusters = await this.pager<CacheCluster>(promise, 'CacheClusters')
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
