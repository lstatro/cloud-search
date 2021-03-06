import { sleepArg } from '../../../../../lib/aws/AWS'
import { RootUser, RootUserMfaEnabledInterface } from './rootUser'

const rule = 'RootUserMfaEnabled'

export const builder = {
  ...sleepArg,
}

export const command = `${rule} [args]`

export const desc = `A root user should had MFA enabled 

  OK      - Root user has MFA enabled
  WARNING - Unable to find the root user in the credentials report
  UNKNOWN - Unable to determine if the root user has MFA enabled 
  FAIL    - Root user does not have MFA enabled

  note: This service works by parsing the IAM credentials report.  If the report
        is not found the service will request a new report and wait a few
        seconds and try again.

        The wait period configurable- by default the CLI sets it to 5 seconds. 
        Consider increasing it if there are a large number of users.

`

export const handler = async (args: RootUserMfaEnabledInterface) => {
  const scanner = new RootUser({ ...args, rule: 'MfaEnabled' })

  await scanner.start()
  scanner.output()
  return scanner.audits
}
