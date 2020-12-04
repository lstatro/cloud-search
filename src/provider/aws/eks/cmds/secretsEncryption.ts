import { CommandBuilder } from 'yargs'
import {
  AuditResultInterface,
  AWSScannerInterface,
} from '@lstatro/cloud-search'
import assert from 'assert'
import { AWS, keyTypeArg } from '../../../../lib/aws/AWS'

const rule = 'SecretsEncryption'

export const command = `${rule} [args]`

export const builder: CommandBuilder = {
  ...keyTypeArg,
}

export const desc = `EKS Clusters should encrypt secrets

  OK      - Cluster uses secrets encryption
  UNKNOWN - Unable to determine if cluster uses secrets encryption
  WARNING - Cluster uses secrets encryption but with the wrong key type
  FAIL    - Cluster does not use secrets encryption

  resourceId - cluster name

`

export class SecretsEncryption extends AWS {
  audits: AuditResultInterface[] = []
  service = 'eks'
  global = false

  constructor(public params: AWSScannerInterface) {
    super({ ...params, rule })
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

    let key

    if (describeCluster.cluster) {
      if (describeCluster.cluster.encryptionConfig) {
        /** we only care about the first key */
        describeCluster.cluster.encryptionConfig.forEach((config) => {
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
    }

    if (key) {
      assert(this.keyType, 'key type is required')
      audit.state = await this.isKeyTrusted(key, this.keyType, region)
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

export const handler = async (args: AWSScannerInterface) => {
  const scanner = new SecretsEncryption(args)

  await scanner.start()
  scanner.output()
  return scanner.audits
}
