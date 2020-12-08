import {
  AuditResultInterface,
  AWSScannerInterface,
} from '@lstatro/cloud-search'
import assert from 'assert'
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

  handleSecretsEncryption = async (
    cluster: Cluster,
    audit: AuditResultInterface,
    region?: string
  ) => {
    let key

    if (cluster.encryptionConfig) {
      /** we only care about the first key */
      cluster.encryptionConfig.forEach((config) => {
        if (config.resources) {
          /**
           * oddly enough the aws sdk says that the only valid value is
           * ['secrets'], this likely means they'll add more in the future
           * lets just go with it, if we find secrets in here then we've
           * got enough data to keep processing
           */
          if (config.resources.includes('secrets')) {
            if (config.provider) {
              if (config.provider.keyArn) {
                key = config.provider.keyArn
              }
            }
          }
        }
      })
    }

    if (key) {
      assert(this.keyType, 'key type is required')
      assert(region, 'region is required')
      audit.state = await this.isKeyTrusted(key, this.keyType, region)
    } else {
      audit.state = 'FAIL'
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
      [key: string]: (
        cluster: Cluster,
        audit: AuditResultInterface,
        region?: string
      ) => void
    } = {
      PublicAccess: this.handlePublicAccess,
      SecretsEncryption: this.handleSecretsEncryption,
    }

    if (describeCluster.cluster) {
      await types[this.rule](describeCluster.cluster, audit, region)
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
