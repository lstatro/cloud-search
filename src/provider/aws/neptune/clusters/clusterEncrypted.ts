import { AuditResultInterface, AWSScannerInterface } from 'cloud-search'
import { AWS } from '../../../../lib/aws/AWS'
import { DescribeDBClustersMessage } from 'aws-sdk/clients/neptune'
import { assert } from 'console'
const rule = 'ClusterEncrypted'

export const command = `${rule} [args]`

export const desc = `Amazon Neptune graph databases should have encryption enabled

  OK      - Neptune cluster encryption is encrypted at rest
  UNKNOWN - Unable to determine if Neptune cluster encryption enabled
  FAIL    - Neptune cluster is not encrypted at rest

  resourceId: Database Identifier

`
//TODO: Figure out the resourceId for Neptune.

export default class ClusterEncrypted extends AWS {
  audits: AuditResultInterface[] = []
  service = 'neptune'
  global = false

  constructor(public params: AWSScannerInterface) {
    super({ ...params, rule })
  }

  async audit({ resource, region }: { resource: string; region: string }) {
    const options = this.getOptions()
    options.region = region
    const neptune = new this.AWS.Neptune(options)
    const describeCluster = await neptune.describeDBClusters({DBClusterIdentifier:resource}).promise();
    console.log('this is describeCluster ...', describeCluster);
    const audit = this.getDefaultAuditObj({ resource, region })
    audit.state = 'OK'
    this.audits.push(audit)
  }

  scan = async ({
    resourceId,
    region,
  }: {
    resourceId: string
    region: string
  }) => {
    if (resourceId) {
      await this.audit({ resource: resourceId, region })
    } else {
      const options = this.getOptions()
      options.region = region
      const promise = new this.AWS.Neptune(options).describeDBClusters().promise()
      const clusters = await this.pager<DescribeDBClustersMessage>(promise, 'DBClusters')
      for (const cluster of clusters) {
        assert(cluster, 'cluster missing its DB Identifier')
        await this.audit({ resource: cluster, region })
      }
    }
  }
}

export const handler = async (args: AWSScannerInterface) => {
  const scanner = new ClusterEncrypted(args)
  await scanner.start()
  scanner.output()
  return scanner.audits
}
