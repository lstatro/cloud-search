import { DetectorId } from 'aws-sdk/clients/guardduty'
import {
  AuditResultInterface,
  AWSScannerInterface,
} from '@lstatro/cloud-search'
import { AWS } from '../../../../lib/aws/AWS'

const rule = 'DetectorExists'

export const command = `${rule} [args]`

export const desc = `A GuardDuty detector exists for this region 

  OK      - A GuardDuty detector exists for this region
  UNKNOWN - Unable to determine if a GuardDuty detector exists in this region
  WARNING - More then one detector found
  FAIL    - Unable to find a single detector for this region

  note: This rule does not validate if the detector is enabled or configured
        properly.  Rather that just a detector exists.  Use DetectorEnabled
        and/or DetectorDataSources for more details about that detector.
  
  note: AWS only allows for one detector per region, but they return detectors
        in an array.  This is misleading, if only one is possible why use a data 
        type that supports multiple?  To avoid overlooking corner cases if more 
        then one detector is found the rule returns WARNING.
`

export class DetectorExists extends AWS {
  audits: AuditResultInterface[] = []
  service = 'guardduty'
  global = false

  constructor(public params: AWSScannerInterface) {
    super({ ...params, rule })
  }

  async audit({ resource, region }: { resource: string[]; region: string }) {
    const options = this.getOptions()
    options.region = region

    const audit = this.getDefaultAuditObj({
      resource: region,
      region: region,
    })

    if (resource.length === 1) {
      audit.state = 'OK'
    } else if (resource.length > 1) {
      audit.state = 'WARNING'
    } else {
      audit.state = 'FAIL'
    }

    this.audits.push(audit)
  }

  scan = async ({ region }: { region: string }) => {
    const options = this.getOptions()
    options.region = region

    const promise = new this.AWS.GuardDuty(options).listDetectors().promise()
    const detectors = await this.pager<DetectorId>(promise, 'DetectorIds')

    await this.audit({ resource: detectors, region })
  }
}

export const handler = async (args: AWSScannerInterface) => {
  const scanner = new DetectorExists(args)
  await scanner.start()
  scanner.output()
  return scanner.audits
}
