import { AWSScannerInterface } from '@lstatro/cloud-search'
import { SecurityConfigSetting } from './securityConfigSetting'

const rule = 'SecurityConfigS3Encryption'

export const command = `${rule} [args]`

export const desc = `EMR security configuration should have s3 encryption 
enabled

  OK      - Security configuration has s3 encryption enabled
  UNKNOWN - Unable to determine if security configuration has s3 enabled
  FAIL    - Security configuration does not have s3 encryption enabled

  resourceId - security configuration name

  note: this rule checks to see if any value is set.  Use bucket scans to audit
        a bucket's encryption level.

`

export const handler = async (args: AWSScannerInterface) => {
  const scanner = new SecurityConfigSetting({
    ...args,
    rule: 'S3Encryption',
  })

  await scanner.start()
  scanner.output()
  return scanner.audits
}
