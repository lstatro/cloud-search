import DetectorDataSources, {
  DetectorDataSourcesInterface,
} from './detectorDataSources'

const rule = 'S3LogsSourceEnable'

export const command = `${rule} [args]`
export const desc = `GuardDuty detectors must have the S3 logs data source enabled

  OK      - The detector has the S3 logs data source enabled 
  UNKNOWN - Unable to determine if the detector ahs the S3 logs source enabled
  FAIL    - The detector does not have the S3 logs data source enabled

  resourceId: detector ID

`

export const handler = async (args: DetectorDataSourcesInterface) => {
  const scanner = new DetectorDataSources({
    ...args,
    source: 'S3Logs',
    rule,
  })
  await scanner.start()
  scanner.output()
  return scanner.audits
}
