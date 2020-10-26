import { AuditResultInterface, AWSScannerInterface } from 'cloud-search'
import { AWS } from '../../../../lib/aws/AWS'

type SourceType = 'CloudTrail' | 'DNSLogs' | 'FlowLogs' | 'S3Logs'

export interface DetectorDataSourcesInterface extends AWSScannerInterface {
  source: SourceType
  rule: string
}

export default class DetectorDataSources extends AWS {
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

    const audit: AuditResultInterface = {
      provider: 'aws',
      physicalId: resource,
      service: this.service,
      rule: this.rule,
      region: region,
      state: 'UNKNOWN',
      profile: this.profile,
      time: new Date().toISOString(),
    }

    const getDetector = await gd
      .getDetector({
        DetectorId: resource,
      })
      .promise()

    if (getDetector.DataSources) {
      if (getDetector.DataSources[this.source].Status) {
        audit.state = 'OK'
      } else {
        audit.state = 'FAIL'
      }
    } else {
      audit.state = 'FAIL'
    }

    this.audits.push(audit)
  }

  scan = async ({
    region,
    resourceId,
  }: {
    region: string
    resourceId: string
  }) => {
    if (resourceId) {
      await this.audit({ resource: resourceId, region })
    } else {
      const detectors = await this.listDetectors(region)
      for (const detector of detectors) {
        await this.audit({ resource: detector, region })
      }
    }
  }
}
