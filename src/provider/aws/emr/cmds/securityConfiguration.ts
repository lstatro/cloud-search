import { AWSScannerInterface } from '@lstatro/cloud-search'
import { EmrCluster } from './emrCluster'

const rule = 'SecurityConfiguration'

export const command = `${rule} [args]`

export const desc = `EMR clusters should launch with a security
configuration group

  OK      - Cluster launched with group
  UNKNOWN - Unable to determine if cluster was launched with a group
  FAIL    - Cluster not launched with group

  resource - cluster ID

`

export const handler = async (args: AWSScannerInterface) => {
  const scanner = new EmrCluster({
    ...args,
    rule,
    attribute: 'SecurityConfiguration',
  })

  await scanner.start()
  scanner.output()
  return scanner.audits
}
