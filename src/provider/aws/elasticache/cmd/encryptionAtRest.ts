import { AuditResultInterface, AWSScannerInterface } from 'cloud-search'
import assert from 'assert'
import { AWS, keyTypeArg } from '../../../../lib/aws/AWS'
import { CacheCluster } from 'aws-sdk/clients/elasticache'

const rule = 'EncryptionAtRest'

export const builder = {
  ...keyTypeArg,
}

export const command = `${rule} [args]`

export const desc = `Elasticache instances should have storage encrypted at rest

  OK      - elasticache cluster storage is encrypted at rest
  WARNING - elasticache cluster storage is encrypted at rest, but with the wrong key type
  UNKNOWN - unable to determine if the elasticache storage is encrypted
  FAIL    - elasticache cluster storage is not encrypted at rest

  resourceId: cluster, instance, or shard name

  note: memcached instances do not support encryption therefore they'll always return FAIL
  note: even standalone instances have a cluster ID

`

export default class AtRestEncryption extends AWS {
  audits: AuditResultInterface[] = []
  service = 'elasticache'
  global = false

  constructor(public params: AWSScannerInterface) {
    super({
      profile: params.profile,
      resourceId: params.resourceId,
      region: params.region,
      verbosity: params.verbosity,
      keyType: params.keyType,
      rule,
    })
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
  const scanner = new AtRestEncryption({
    region: args.region,
    profile: args.profile,
    resourceId: args.resourceId,
    keyType: args.keyType,
    verbosity: args.verbosity,
  })

  await scanner.start()
  scanner.output()
  return scanner.audits
}
