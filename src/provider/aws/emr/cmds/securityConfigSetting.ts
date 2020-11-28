import {
  AuditResultInterface,
  AWSScannerInterface,
} from '@lstatro/cloud-search'
import assert from 'assert'
import { AWS } from '../../../../lib/aws/AWS'

export type ClusterAttributeType = 'SecurityConfiguration' | 'LogUri'

export interface SecurityConfigSettingInterface extends AWSScannerInterface {
  rule: 'S3Encryption' | 'DiskEncryption' | 'TransitEncryption'
}

export interface ConfigHandlerInterface {
  securityConfiguration: string
  audit: AuditResultInterface
}

export class SecurityConfigSetting extends AWS {
  audits: AuditResultInterface[] = []
  service = 'emr'
  global = false

  constructor(public params: SecurityConfigSettingInterface) {
    super({ ...params })
  }

  handleS3Encryption = (params: ConfigHandlerInterface) => {
    let found = false
    const config = JSON.parse(params.securityConfiguration)
    if (config.EncryptionConfiguration) {
      if (config.EncryptionConfiguration.AtRestEncryptionConfiguration) {
        if (
          config.EncryptionConfiguration.AtRestEncryptionConfiguration
            .S3EncryptionConfiguration
        ) {
          if (
            config.EncryptionConfiguration.AtRestEncryptionConfiguration
              .S3EncryptionConfiguration.EncryptionMode
          ) {
            found = true
          }
        }
      }
    }
    if (found) {
      params.audit.state = 'OK'
    } else {
      params.audit.state = 'FAIL'
    }
  }

  handleDiskEncryption = (params: ConfigHandlerInterface) => {
    let found = false
    const config = JSON.parse(params.securityConfiguration)
    if (config.EncryptionConfiguration) {
      if (config.EncryptionConfiguration.AtRestEncryptionConfiguration) {
        if (
          config.EncryptionConfiguration.AtRestEncryptionConfiguration
            .LocalDiskEncryptionConfiguration
        ) {
          if (
            config.EncryptionConfiguration.AtRestEncryptionConfiguration
              .LocalDiskEncryptionConfiguration.EnableEbsEncryption
          ) {
            found = true
          }
        }
      }
    }
    if (found) {
      params.audit.state = 'OK'
    } else {
      params.audit.state = 'FAIL'
    }
  }

  handleTransitEncryption = (params: ConfigHandlerInterface) => {
    let found = false
    const config = JSON.parse(params.securityConfiguration)
    if (config.EncryptionConfiguration) {
      if (config.EncryptionConfiguration.EnableInTransitEncryption) {
        found = true
      }
    }

    if (found) {
      params.audit.state = 'OK'
    } else {
      params.audit.state = 'FAIL'
    }
  }

  async audit({ resource, region }: { resource: string; region: string }) {
    const options = this.getOptions()
    options.region = region

    const audit = this.getDefaultAuditObj({ resource, region })

    const configuration = await new this.AWS.EMR(options)
      .describeSecurityConfiguration({
        Name: resource,
      })
      .promise()

    try {
      if (configuration.SecurityConfiguration) {
        const types: {
          [key: string]: (params: ConfigHandlerInterface) => void
        } = {
          S3Encryption: this.handleS3Encryption,
          DiskEncryption: this.handleDiskEncryption,
          TransitEncryption: this.handleTransitEncryption,
        }

        types[this.rule]({
          securityConfiguration: configuration.SecurityConfiguration,
          audit,
        })
      } else {
        audit.state = 'FAIL'
      }
    } catch (err) {
      audit.state = 'WARNING'
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
      const configurations = await new this.AWS.EMR(options)
        .listSecurityConfigurations()
        .promise()

      if (configurations.SecurityConfigurations) {
        for (const configuration of configurations.SecurityConfigurations) {
          assert(configuration.Name, 'security config did not provide a name')
          await this.audit({ resource: configuration.Name, region })
        }
      }
    }
  }
}
