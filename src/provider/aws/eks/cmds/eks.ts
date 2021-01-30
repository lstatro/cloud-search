import {
  AWSScannerInterface,
  AuditResultInterface,
} from '@lstatro/cloud-search'

import { AWS } from '../../../../lib/aws/AWS'
import { Cluster } from 'aws-sdk/clients/eks'
import assert from 'assert'

export type LoggingType =
  | 'api'
  | 'audit'
  | 'authenticator'
  | 'controllerManager'
  | 'scheduler'

export interface EksInterface extends AWSScannerInterface {
  rule:
    | 'SecretsEncryption'
    | 'PublicAccess'
    | 'AuditLogging'
    | 'ApiLogging'
    | 'AuthenticatorLogging'
    | 'ControllerManagerLogging'
    | 'SchedulerLogging'
}

export class Eks extends AWS {
  audits: AuditResultInterface[] = []
  service = 'eks'
  global = false
  loggingType?: LoggingType

  constructor(public params: EksInterface) {
    super({ ...params })
    const types: { [key: string]: LoggingType } = {
      AuditLogging: 'audit',
      ApiLogging: 'api',
      AuthenticatorLogging: 'authenticator',
      ControllerManagerLogging: 'controllerManager',
      SchedulerLogging: 'scheduler',
    }
    this.loggingType = types[params.rule]
  }

  handleLogging = ({
    cluster,
    audit,
  }: {
    cluster: Cluster
    audit: AuditResultInterface
  }) => {
    let found = false

    assert(this.loggingType, 'eks log type is required')

    if (cluster.logging) {
      if (cluster.logging.clusterLogging) {
        for (const logging of cluster.logging.clusterLogging) {
          if (logging.enabled === true) {
            if (logging.types) {
              if (logging.types.includes(this.loggingType)) {
                found = true
              }
            }
          }
        }
      }
    }

    if (found === true) {
      audit.state = 'OK'
    } else {
      audit.state = 'FAIL'
    }
  }

  handlePublicAccess = ({
    cluster,
    audit,
  }: {
    cluster: Cluster
    audit: AuditResultInterface
  }) => {
    if (cluster.resourcesVpcConfig) {
      if (cluster.resourcesVpcConfig.endpointPublicAccess === false) {
        audit.state = 'OK'
      } else {
        audit.state = 'FAIL'
      }
    }
  }

  handleSecretsEncryption = async ({
    cluster,
    audit,
    region,
  }: {
    cluster: Cluster
    audit: AuditResultInterface
    region?: string
  }) => {
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
      [key: string]: ({
        cluster,
        audit,
        region,
      }: {
        cluster: Cluster
        audit: AuditResultInterface
        region?: string
      }) => void
    } = {
      PublicAccess: this.handlePublicAccess,
      SecretsEncryption: this.handleSecretsEncryption,
      AuditLogging: this.handleLogging,
      ApiLogging: this.handleLogging,
      AuthenticatorLogging: this.handleLogging,
      ControllerManagerLogging: this.handleLogging,
      SchedulerLogging: this.handleLogging,
    }

    if (describeCluster.cluster) {
      await types[this.rule]({
        cluster: describeCluster.cluster,
        audit,
        region,
      })
    }

    this.audits.push(audit)
  }

  scan = async ({ resource, region }: { resource: string; region: string }) => {
    if (resource) {
      await this.audit({ resource: resource, region })
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
