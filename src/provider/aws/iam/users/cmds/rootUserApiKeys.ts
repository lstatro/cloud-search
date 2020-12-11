import { sleepArg } from '../../../../../lib/aws/AWS'
import { RootUser, RootUserMfaEnabledInterface } from './rootUser'

const rule = 'RootUserApiKeys'

export const builder = {
  ...sleepArg,
}

export const command = `${rule} [args]`

export const desc = `A root user should not have active API keys 

  OK      - Root user does not have API keys
  WARNING - root user has API keys but they are inactive
  UNKNOWN - Unable to determine if the root user has API keys 
  FAIL    - Root user has active API keys

  note: This service works by parsing the IAM credentials report.  If the report
        is not found the service will request a new report and wait a few
        seconds and try again.

        The wait period configurable- by default the CLI sets it to 5 seconds. 
        Consider increasing it if there are a large number of users.

  note: Users may have up to two keys, if either key slot is active this rule
        will report fail

`

export const handler = async (args: RootUserMfaEnabledInterface) => {
  const scanner = new RootUser({ ...args, rule: 'ApiKeys' })

  await scanner.start()
  scanner.output()
  return scanner.audits
}
