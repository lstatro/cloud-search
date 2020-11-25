import {
  AuditResultInterface,
  AWSScannerInterface,
} from '@lstatro/cloud-search'
import assert from 'assert'
import { AWS } from '../../../../lib/aws/AWS'

export type ClusterAttributeType = 'SecurityConfiguration' | 'LogUri'

export interface EmrClusterInterface extends AWSScannerInterface {
  rule: 'LoggingEnabled' | 'SecurityConfiguration'
  attribute: ClusterAttributeType
}

export class EmrCluster extends AWS {
  audits: AuditResultInterface[] = []
  service = 'emr'
  global = false
  attribute: ClusterAttributeType

  constructor(public params: EmrClusterInterface) {
    super({ ...params })
    this.attribute = params.attribute
  }

  async audit({ resource, region }: { resource: string; region: string }) {
    const options = this.getOptions()
    options.region = region

    assert(resource, 'emr cluster id is required')

    const audit = this.getDefaultAuditObj({ resource: resource, region })

    const describeCluster = await new this.AWS.EMR(options)
      .describeCluster({
        ClusterId: resource,
      })
      .promise()

    if (describeCluster.Cluster) {
      if (describeCluster.Cluster[this.attribute]) {
        audit.state = 'OK'
      } else {
        audit.state = 'FAIL'
      }
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
    const options = this.getOptions()
    options.region = region

    if (resourceId) {
      await this.audit({ resource: resourceId, region })
    } else {
      const listClusters = await new this.AWS.EMR(options)
        .listClusters({
          ClusterStates: [
            'STARTING',
            'BOOTSTRAPPING',
            'RUNNING',
            'WAITING',
            'TERMINATING',
          ],
        })
        .promise()

      if (listClusters.Clusters) {
        for (const cluster of listClusters.Clusters) {
          assert(cluster.Id, 'cluster ID not found')
          await this.audit({ resource: cluster.Id, region })
        }
      }
    }
  }
}
