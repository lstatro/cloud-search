import { AuditResultInterface, AWSScannerInterface } from 'cloud-search'
import assert from 'assert'
import { AWS, keyTypeArg } from '../../../../lib/aws/AWS'
import { DBCluster } from 'aws-sdk/clients/rds'

const rule = 'ClusterEncrypted'

export const builder = {
  ...keyTypeArg,
}

export const command = `${rule} [args]`

export const desc = `RDS clusters must have their storage at rest encrypted

  OK      - RDS cluster storage is encrypted at rest
  UNKNOWN - unable to determine if the storage is encrypted at rest
  WARNING - RDS cluster storage is encrypted but not with the specified key type
  FAIL    - RDS cluster storage is not encrypted at rest

  resourceId: RDS clusters ARN

  note: this rule targets DB Clusters not DB Instances' (MySQL, PostgreSQL, Oracle, MariaDB, MSSQL).

`

export default class ClusterEncrypted extends AWS {
  audits: AuditResultInterface[] = []
  service = 'rds'
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

  async audit({ resource, region }: { resource: DBCluster; region: string }) {
    assert(resource.DBClusterArn, 'cluster does not have a cluster ARN')
    const audit: AuditResultInterface = {
      provider: 'aws',
      physicalId: resource.DBClusterArn,
      service: this.service,
      rule: this.rule,
      region: region,
      state: 'UNKNOWN',
      profile: this.profile,
      time: new Date().toISOString(),
    }

    if (typeof resource.KmsKeyId === 'string') {
      /** if there is a key it should be encrypted, if not, something unexpected is going on */
      assert(
        resource.StorageEncrypted === true,
        'key found, but rds instance is not encrypted'
      )
      assert(this.keyType, 'key type is required')
      audit.state = await this.isKeyTrusted(
        resource.KmsKeyId,
        this.keyType,
        region
      )
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
      clusters = await this.listDBClusters(region, resourceId)
    } else {
      clusters = await this.listDBClusters(region)
    }

    for (const cluster of clusters) {
      assert(cluster.DBClusterArn, 'a cluster must have a ARN')
      await this.audit({
        resource: cluster,
        region,
      })
    }
  }
}

export const handler = async (args: AWSScannerInterface) => {
  const scanner = new ClusterEncrypted({
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
