import { Elbv2AccessLogsEnabled } from './elbv2AccessLogsEnabled'

const rule = 'NlbAccessLogsEnabled'

export const command = `${rule} [args]`
export const desc = `Verifies network load balancers have access logging

  OK      - LB has logging enabled
  WARNING - LB has logging enabled but does not have a target s3 bucket
  UNKNOWN - Unable to determine if LB has logging enabled
  FAIL    - LB does not have logging enabled

  resourceId - load balancer name

`

export const handler = async (args: AWSScannerInterface) => {
  const scanner = await new Elbv2AccessLogsEnabled({
    ...args,
    rule,
    type: 'network',
  })
  await scanner.start()
  scanner.output()
  return scanner.audits
}
