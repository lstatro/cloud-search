import { SecurityConfigSetting } from './securityConfigSetting'

const rule = 'SecurityConfigDiskEncryption'

export const command = `${rule} [args]`

export const desc = `EMR security configuration should have disk encryption
enabled

  OK      - Security configuration has disk encryption enabled
  UNKNOWN - Unable to determine if security configuration has disk encryption enabled
  FAIL    - Security configuration does not have disk encryption enabled

  resourceId - security configuration name

  note: this rule checks to see if any value is set.  Use volume scans to audit
        a volume's encryption level.
`

export const handler = async (args: AWSScannerInterface) => {
  const scanner = new SecurityConfigSetting({
    ...args,
    rule: 'DiskEncryption',
  })

  await scanner.start()
  scanner.output()
  return scanner.audits
}
