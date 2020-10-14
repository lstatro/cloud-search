/** TODO: can this be handled by iam.simulatePrincipalPolicy? */

import { AuditResultInterface, AWSScannerInterface } from 'cloud-search'
import assert from 'assert'
import AWS from '../../../../lib/aws/AWS'
import { DBCluster } from 'aws-sdk/clients/rds'

const rule = 'ClusterEncrypted'

export const command = `${rule} [args]`

export const desc = `RDS clusters must have their stroage at rest encrypted

  OK      - RDS cluster storage is encrypted at rest
  UNKNOWN - unable to determine if the storage is encrypted at rest
  FAIL    - RDS cluster storage is not encrypted at rest

  resourceId: RDS clusters ARN

  note: this rule targets DB Clusters not DB Instances' (MySQL, PostgreSQL, Oracle, MariaDB, MSSQL).

`

export default class PublicClusters extends AWS {
  audits: AuditResultInterface[] = []
  service = 'rds'
  global = false

  constructor(public params: AWSScannerInterface) {
    super({
      profile: params.profile,
      resourceId: params.resourceId,
      region: params.region,
      rule,
    })
  }

  async audit({
    resourceId,
    region,
  }: {
    resourceId: DBCluster
    region: string
  }) {
    const auditObject: AuditResultInterface = {
      provider: 'aws',
      physicalId: resourceId,
      service: this.service,
      rule: this.rule,
      region: region,
      state: 'UNKNOWN',
      profile: this.profile,
      time: new Date().toISOString(),
    }

    // this.isKeyTrusted(resourceId.KmsKeyId)
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
        resourceId: cluster,
        region,
      })
    }
  }
}

export const handler = async (args: AWSScannerInterface) => {
  const scanner = new PublicClusters({
    region: args.region,
    profile: args.profile,
    resourceId: args.resourceId,
  })

  await scanner.start()
  scanner.output()
  return scanner.audits
}
