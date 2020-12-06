import {
  AuditResultInterface,
  AWSScannerInterface,
} from '@lstatro/cloud-search'
import { Cluster } from 'aws-sdk/clients/eks'
import { AWS } from '../../../../lib/aws/AWS'

export interface EksInterface extends AWSScannerInterface {
  rule: 'SecretsEncryption' | 'PublicAccess'
}

export class Eks extends AWS {
  audits: AuditResultInterface[] = []
  service = 'eks'
  global = false

  constructor(public params: EksInterface) {
    super({ ...params })
  }

  handlePublicAccess = (cluster: Cluster, audit: AuditResultInterface) => {
    if (cluster.resourcesVpcConfig) {
      if (cluster.resourcesVpcConfig.endpointPublicAccess === false) {
        audit.state = 'OK'
      } else {
        audit.state = 'FAIL'
      }
    }
  }

  async audit({ resource, region }: { resource: string; region: string }) {
    const options = this.getOptions()
    options.region = region

    const audit = this.getDefaultAuditObj({ resource, region })

    const describeCluster = await new this.AWS.EKS(options)
      .describeCluster({
        name: resource,
      })
      .promise()

    const types: {
      [key: string]: (cluster: Cluster, audit: AuditResultInterface) => void
    } = {
      PublicAccess: this.handlePublicAccess,
    }

    if (describeCluster.cluster) {
      await types[this.rule](describeCluster.cluster, audit)
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
    if (resourceId) {
      await this.audit({ resource: resourceId, region })
    } else {
      const options = this.getOptions()
      options.region = region
      const promise = new this.AWS.EKS(options).listClusters().promise()
      const clusters = await this.pager<string>(promise, 'clusters')
      for (const cluster of clusters) {
        await this.audit({ resource: cluster, region })
      }
    }
  }
}
