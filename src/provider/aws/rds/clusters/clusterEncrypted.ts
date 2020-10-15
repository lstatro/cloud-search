import { CommandBuilder } from 'yargs'
import { AuditResultInterface, AWSScannerInterface } from 'cloud-search'
import assert from 'assert'
import AWS from '../../../../lib/aws/AWS'
import { DBCluster } from 'aws-sdk/clients/rds'
import { AWSScannerCliArgsInterface } from 'cloud-search'

const rule = 'ClusterEncrypted'

export const builder: CommandBuilder = {
  keyType: {
    alias: 't',
    describe: 'the AWS key type',
    type: 'string',
    default: 'aws',
    choices: ['aws', 'cmk'],
  },
}

export const command = `${rule} [args]`

export const desc = `RDS clusters must have their stroage at rest encrypted

  OK      - RDS cluster storage is encrypted at rest
  UNKNOWN - unable to determine if the storage is encrypted at rest
  WARNING - RDS cluster storage is encrypted but not with the specified key type
  FAIL    - RDS cluster storage is not encrypted at rest

  resourceId: RDS clusters ARN

  note: this rule targets DB Clusters not DB Instances' (MySQL, PostgreSQL, Oracle, MariaDB, MSSQL).

`

export interface ClusterEncryptedInterface extends AWSScannerInterface {
  keyType: 'aws' | 'cmk'
}

export interface ClusterEncryptedCliInterface
  extends ClusterEncryptedInterface,
    AWSScannerCliArgsInterface {}

export default class ClusterEncrypted extends AWS {
  audits: AuditResultInterface[] = []
  service = 'rds'
  global = false
  keyId?: string
  keyType: 'aws' | 'cmk'

  constructor(public params: ClusterEncryptedInterface) {
    super({
      profile: params.profile,
      resourceId: params.resourceId,
      region: params.region,
      rule,
    })
    this.keyType = params.keyType
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
      physicalId: resourceId.DBClusterArn,
      service: this.service,
      rule: this.rule,
      region: region,
      state: 'UNKNOWN',
      profile: this.profile,
      time: new Date().toISOString(),
    }

    if (typeof resourceId.KmsKeyId === 'string') {
      /** if there is a key it should be encrypted, if not, something unexpected is going on */
      assert(
        resourceId.StorageEncrypted === true,
        'key found, but rds instance is not encrypted'
      )
      auditObject.state = await this.isKeyTrusted(
        resourceId.KmsKeyId,
        this.keyType,
        region
      )
    } else {
      auditObject.state = 'FAIL'
    }
    this.audits.push(auditObject)
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

export const handler = async (args: ClusterEncryptedCliInterface) => {
  const scanner = new ClusterEncrypted({
    region: args.region,
    profile: args.profile,
    resourceId: args.resourceId,
    keyType: args.keyType,
  })

  await scanner.start()
  scanner.output()
  return scanner.audits
}