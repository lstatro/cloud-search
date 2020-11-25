import {
  AuditResultInterface,
  AWSScannerInterface,
} from '@lstatro/cloud-search'
import assert from 'assert'
import { AWS } from '../../../../lib/aws/AWS'

export type ClusterAttributeType = 'SecurityConfiguration' | 'LogUri'

export interface SecurityConfigSettingInterface extends AWSScannerInterface {
  rule: 'S3Encryption'
}

export class SecurityConfigSetting extends AWS {
  audits: AuditResultInterface[] = []
  service = 'emr'
  global = false

  constructor(public params: SecurityConfigSettingInterface) {
    super({ ...params })
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

    let found = false

    try {
      if (configuration.SecurityConfiguration) {
        const config = JSON.parse(configuration.SecurityConfiguration)
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
      }
      if (found) {
        audit.state = 'OK'
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
