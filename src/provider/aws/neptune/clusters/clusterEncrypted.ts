import { AWS, keyTypeArg } from '../../../../lib/aws/AWS'
import {
  AWSScannerInterface,
  AuditResultInterface,
} from '@lstatro/cloud-search'

import { DBCluster } from 'aws-sdk/clients/neptune'
import assert from 'assert'

const rule = 'ClusterEncrypted'

export const command = `${rule} [args]`

export const desc = `Amazon Neptune graph cluster databases should have encryption at rest enabled

  OK      - Neptune cluster encryption is encrypted at rest
  UNKNOWN - Unable to determine if Neptune cluster encryption enabled
  FAIL    - Neptune cluster is not encrypted at rest

  resource: Database Identifier

`
export const builder = {
  ...keyTypeArg,
}

export class ClusterEncrypted extends AWS {
  audits: AuditResultInterface[] = []
  service = 'neptune'
  global = false

  constructor(public params: AWSScannerInterface) {
    super({ ...params, rule })
  }

  async audit({ resource, region }: { resource: DBCluster; region: string }) {
    const options = this.getOptions()
    options.region = region
    assert(resource.DBClusterIdentifier, 'cluster missing its DB Identifier')
    const audit = this.getDefaultAuditObj({
      resource: resource.DBClusterIdentifier,
      region,
    })
    if (resource.KmsKeyId) {
      assert(
        this.keyType,
        'Key type is required argument for isKeyTrusted check'
      )
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

  scan = async ({ resource, region }: { resource: string; region: string }) => {
    let clusters
    const options = this.getOptions()
    options.region = region
    if (resource) {
      const promise = new this.AWS.Neptune(options)
        .describeDBClusters({
          DBClusterIdentifier: resource,
        })
        .promise()
      clusters = await this.pager<DBCluster>(promise, 'DBClusters')
    } else {
      const promise = new this.AWS.Neptune(options)
        .describeDBClusters()
        .promise()
      clusters = await this.pager<DBCluster>(promise, 'DBClusters')
    }
    for (const cluster of clusters) {
      await this.audit({ resource: cluster, region })
    }
  }
}

export const handler = async (args: AWSScannerInterface) => {
  const scanner = new ClusterEncrypted(args)
  await scanner.start()
  scanner.output()
  return scanner.audits
}
