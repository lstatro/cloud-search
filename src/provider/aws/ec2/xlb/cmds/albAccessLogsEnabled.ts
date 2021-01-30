import { AWSScannerInterface } from '@lstatro/cloud-search'
import { Elbv2AccessLogsEnabled } from './elbv2AccessLogsEnabled'

const rule = 'AlbAccessLogsEnabled'

export const command = `${rule} [args]`
export const desc = `Verifies application load balancers has access logging
enabled

  OK      - LB has logging enabled
  WARNING - LB has logging enabled but does not have a target s3 bucket
  UNKNOWN - Unable to determine if LB has logging enabled
  FAIL    - LB does not have logging enabled

  resource - load balancer name

`

export const handler = async (args: AWSScannerInterface) => {
  const scanner = await new Elbv2AccessLogsEnabled({
    ...args,
    rule,
    type: 'application',
  })
  await scanner.start()
  scanner.output()
  return scanner.audits
}
