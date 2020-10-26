import DetectorDataSources, {
  DetectorDataSourcesInterface,
} from './detectorDataSources'

const rule = 'AllDataSources'

export const command = `${rule} [args]`
export const desc = `run all GuardDuty source checks

`

export const handler = async (args: DetectorDataSourcesInterface) => {
  const s3Logs = new DetectorDataSources({
    ...args,
    source: 'S3Logs',
    rule: 'S3LogsSourceEnable',
  })
  await s3Logs.start()

  const cloudTrail = new DetectorDataSources({
    ...args,
    source: 'CloudTrail',
    rule: 'CloudTrailSourceEnable',
  })
  await cloudTrail.start()

  const flowLogs = new DetectorDataSources({
    ...args,
    source: 'FlowLogs',
    rule: 'FlowLogsSourceEnable',
  })
  await flowLogs.start()

  const dnsLogs = new DetectorDataSources({
    ...args,
    source: 'DNSLogs',
    rule: 'DNSLogsSourceEnable',
  })
  await dnsLogs.start()

  const audits = [
    ...s3Logs.audits,
    ...cloudTrail.audits,
    ...flowLogs.audits,
    ...dnsLogs.audits,
  ]

  dnsLogs.audits = audits

  dnsLogs.output()
  return audits
}
