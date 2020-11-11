import { DetectorId } from 'aws-sdk/clients/guardduty'
import {
  AuditResultInterface,
  AWSScannerInterface,
} from '@lstatro/cloud-search'
import { AWS } from '../../../../lib/aws/AWS'

const rule = 'DetectorEnabled'

export const command = `${rule} [args]`

export const desc = `Existing GuardDuty detectors are enabled

  OK      - Detector is enabled
  UNKNOWN - Unable to determine if the detector is enabled
  FAIL    - Detector is not enabled

  note: This rule applies to existing GuardDuty detectors.  If the detector 
        does not exist there is nothing to report on, use DetectorExists if
        looking to see if a detector exists in the targeted region.
`

export default class DetectorEnabled extends AWS {
  audits: AuditResultInterface[] = []
  service = 'guardduty'
  global = false

  constructor(public params: AWSScannerInterface) {
    super({ ...params, rule })
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

    if (getDetector.Status === 'ENABLED') {
      audit.state = 'OK'
    } else if (getDetector.Status === 'DISABLED') {
      audit.state = 'FAIL'
    }

    this.audits.push(audit)
  }

  scan = async ({ region }: { region: string }) => {
    const options = this.getOptions()
    options.region = region

    const promise = new this.AWS.GuardDuty(options).listDetectors().promise()
    const detectors = await this.pager<DetectorId>(promise, 'DetectorIds')

    for (const detector of detectors) {
      await this.audit({ resource: detector, region })
    }
  }
}

export const handler = async (args: AWSScannerInterface) => {
  const scanner = new DetectorEnabled(args)
  await scanner.start()
  scanner.output()
  return scanner.audits
}
