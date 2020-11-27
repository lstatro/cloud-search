import { AWSScannerInterface } from '@lstatro/cloud-search'
import { SecurityConfigSetting } from './securityConfigSetting'

const rule = 'SecurityConfigTransitEncryption'

export const command = `${rule} [args]`

export const desc = `EMR security configuration should have transit encryption
enabled

  OK      - Security configuration has transit encryption enabled
  UNKNOWN - Unable to determine if security configuration has transit encryption enabled
  FAIL    - Security configuration does not have transit encryption enabled

  resourceId - security configuration name

  note: this rule checks to see if any value is set
`

export const handler = async (args: AWSScannerInterface) => {
  const scanner = new SecurityConfigSetting({
    ...args,
    rule: 'TransitEncryption',
  })

  await scanner.start()
  scanner.output()
  return scanner.audits
}
