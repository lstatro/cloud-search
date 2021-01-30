import {
  DetectorDataSources,
  DetectorDataSourcesInterface,
} from './detectorDataSources'

const rule = 'CloudTrailSourceEnable'

export const command = `${rule} [args]`
export const desc = `GuardDuty detectors must have the CloudTrail data source enabled

  OK      - The detector has the CloudTrail data source enabled 
  UNKNOWN - Unable to determine if the detector ahs the CloudTrail source enabled
  FAIL    - The detector does not have the CloudTrail data source enabled

  resource: detector ID

`

export const handler = async (args: DetectorDataSourcesInterface) => {
  const scanner = new DetectorDataSources({
    ...args,
    source: 'CloudTrail',
    rule,
  })
  await scanner.start()
  scanner.output()
  return scanner.audits
}
