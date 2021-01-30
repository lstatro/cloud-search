import {
  AWSScannerInterface,
  AuditResultInterface,
} from '@lstatro/cloud-search'

import { AWS } from '../../../../lib/aws/AWS'
import { DetectorId } from 'aws-sdk/clients/guardduty'

export type SourceType = 'CloudTrail' | 'DNSLogs' | 'FlowLogs' | 'S3Logs'

export interface DetectorDataSourcesInterface extends AWSScannerInterface {
  source: SourceType
  rule: string
}

export class DetectorDataSources extends AWS {
  audits: AuditResultInterface[] = []
  service = 'guardduty'
  global = false
  source: SourceType

  constructor(public params: DetectorDataSourcesInterface) {
    super({ ...params, rule: params.rule })
    this.source = params.source
  }

  async audit({ resource, region }: { resource: string; region: string }) {
    const options = this.getOptions()
    options.region = region

    const gd = new this.AWS.GuardDuty(options)

    const audit = this.getDefaultAuditObj({
      resource: resource,
      region: region,
    })

    const getDetector = await gd
      .getDetector({
        DetectorId: resource,
      })
      .promise()

    const dataSources = getDetector.DataSources
    if (dataSources) {
      const status = dataSources[this.source].Status

      if (status === 'ENABLED') {
        audit.state = 'OK'
      } else {
        audit.state = 'FAIL'
      }
    } else {
      audit.state = 'FAIL'
    }

    this.audits.push(audit)
  }

  scan = async ({ region, resource }: { region: string; resource: string }) => {
    if (resource) {
      await this.audit({ resource: resource, region })
    } else {
      const options = this.getOptions()
      options.region = region

      const promise = new this.AWS.GuardDuty(options).listDetectors().promise()
      const detectors = await this.pager<DetectorId>(promise, 'DetectorIds')

      for (const detector of detectors) {
        await this.audit({ resource: detector, region })
      }
    }
  }
}
