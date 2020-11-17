import {
  DetectorDataSources,
  DetectorDataSourcesInterface,
} from './detectorDataSources'

const rule = 'DNSLogsSourceEnable'

export const command = `${rule} [args]`
export const desc = `GuardDuty detectors must have the DNSLogs data source enabled

  OK      - The detector has the DNSLogs data source enabled 
  UNKNOWN - Unable to determine if the detector ahs the DNSLogs source enabled
  FAIL    - The detector does not have the DNSLogs data source enabled

  resourceId: detector ID

`

export const handler = async (args: DetectorDataSourcesInterface) => {
  const scanner = new DetectorDataSources({
    ...args,
    source: 'DNSLogs',
    rule,
  })

  await scanner.start()
  scanner.output()
  return scanner.audits
}
