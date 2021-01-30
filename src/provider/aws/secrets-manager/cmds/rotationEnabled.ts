import { AWSScannerInterface } from '@lstatro/cloud-search'
import { SecretsManager } from './secretsManager'

const rule = 'RotationEnabled'

export const command = `${rule} [args]`

export const desc = `Secrets Manager passwords should have automatic rotation enabled

  OK      - Rotation enabled
  UNKNOWN - Unable to determine if rotation is enabled
  FAIL    - Rotation is not enabled

  resource: secret name

`

export const handler = async (args: AWSScannerInterface) => {
  const scanner = new SecretsManager({ ...args, rule })

  await scanner.start()
  scanner.output()
  return scanner.audits
}
