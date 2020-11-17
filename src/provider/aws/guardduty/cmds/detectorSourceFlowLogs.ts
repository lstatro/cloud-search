import {
  DetectorDataSources,
  DetectorDataSourcesInterface,
} from './detectorDataSources'

const rule = 'FlowLogsSourceEnable'

export const command = `${rule} [args]`
export const desc = `GuardDuty detectors must have the flow logs data source enabled

  OK      - The detector has the flow logs data source enabled 
  UNKNOWN - Unable to determine if the detector ahs the flow logs source enabled
  FAIL    - The detector does not have the flow logs data source enabled

  resourceId: detector ID

`

export const handler = async (args: DetectorDataSourcesInterface) => {
  const scanner = new DetectorDataSources({
    ...args,
    source: 'FlowLogs',
    rule,
  })
  await scanner.start()
  scanner.output()
  return scanner.audits
}
