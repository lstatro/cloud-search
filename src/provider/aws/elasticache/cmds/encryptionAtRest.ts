import { AWS, keyTypeArg } from '../../../../lib/aws/AWS'

import { CacheCluster } from 'aws-sdk/clients/elasticache'
import assert from 'assert'

const rule = 'EncryptionAtRest'

export const builder = {
  ...keyTypeArg,
}

export const command = `${rule} [args]`

export const desc = `Elasticache instances should have storage encrypted at rest

  OK      - Elasticache cluster storage is encrypted at rest
  WARNING - Elasticache cluster storage is encrypted at rest, but with the wrong key type
  UNKNOWN - Unable to determine if the elasticache storage is encrypted
  FAIL    - Elasticache cluster storage is not encrypted at rest

  resourceId: cluster, instance, or shard name

  note: Memcached instances do not support encryption therefore they'll always return FAIL
  note: Even standalone instances have a cluster ID

`

export class EncryptionAtRest extends AWS {
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

    if (resource.AtRestEncryptionEnabled) {
      if (resource.Engine === 'redis') {
        await this.handleRedis({
          resource,
          region,
          audit,
        })
      }
    } else {
      audit.state = 'FAIL'
    }

    this.audits.push(audit)
  }

  handleRedis = async ({
    resource,
    region,
    audit,
  }: {
    resource: CacheCluster
    region: string
    audit: AuditResultInterface
  }) => {
    const options = this.getOptions()
    options.region = region

    assert(
      resource.ReplicationGroupId,
      'all redis clusters must have a replication group id'
    )

    const groups = await new this.AWS.ElastiCache(options)
      .describeReplicationGroups({
        ReplicationGroupId: resource.ReplicationGroupId,
      })
      .promise()

    if (groups.ReplicationGroups) {
      assert(
        Array.isArray(groups.ReplicationGroups),
        'expecting group to be an array'
      )

      assert(
        groups.ReplicationGroups.length === 1,
        'expecting a single resource in the group'
      )

      for (const group of groups.ReplicationGroups) {
        if (group.KmsKeyId) {
          assert(this.keyType, 'key type is required')
          audit.state = await this.isKeyTrusted(
            group.KmsKeyId,
            this.keyType,
            region
          )
        } else {
          audit.state = 'FAIL'
        }
      }
    }
  }

  scan = async ({
    resourceId,
    region,
  }: {
    resourceId: string
    region: string
  }) => {
    let clusters
    const options = this.getOptions()
    options.region = region

    if (resourceId) {
      const promise = new this.AWS.ElastiCache(options)
        .describeCacheClusters({
          CacheClusterId: resourceId,
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
  const scanner = new EncryptionAtRest(args)

  await scanner.start()
  scanner.output()
  return scanner.audits
}
