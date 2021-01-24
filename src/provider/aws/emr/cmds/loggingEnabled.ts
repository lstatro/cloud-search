import { EmrCluster } from './emrCluster'

const rule = 'LoggingEnabled'

export const command = `${rule} [args]`

export const desc = `EMR clusters should have logging enabled

  OK      - Cluster is logging
  UNKNOWN - Unable to determine if cluster is logging
  FAIL    - Cluster is not logging

  resourceId - cluster ID

`

export const handler = async (args: AWSScannerInterface) => {
  const scanner = new EmrCluster({
    ...args,
    rule,
    attribute: 'LogUri',
  })

  await scanner.start()
  scanner.output()
  return scanner.audits
}
