import { AWSScannerInterface } from '@lstatro/cloud-search'
import { SecretsManager } from './secretsManager'

const rule = 'SecretEncryptedWithCmk'

export const command = `${rule} [args]`

export const desc = `Secrets Manager secrets should be encrypted with a CMK

  OK      - Secret encrypted with a CMK
  UNKNOWN - Unable to determine if secret is encrypted with a CMK
  FAIL    - Secret is not encrypted with a CMK

  resource: secret name

  note: Secrets are always encrypted by default with an AWS managed KMS key.  
        However customers have no control over these keys.
`

export const handler = async (args: AWSScannerInterface) => {
  const scanner = new SecretsManager({ ...args, rule })

  await scanner.start()
  scanner.output()
  return scanner.audits
}
