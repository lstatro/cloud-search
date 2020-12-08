import { CommandBuilder } from 'yargs'
import { keyTypeArg } from '../../../../lib/aws/AWS'
import { Eks, EksInterface } from './eks'

const rule = 'SecretsEncryption'

export const command = `${rule} [args]`

export const builder: CommandBuilder = {
  ...keyTypeArg,
}

export const desc = `EKS Clusters should encrypt secrets

  OK      - Cluster uses secrets encryption
  UNKNOWN - Unable to determine if cluster uses secrets encryption
  WARNING - Cluster uses secrets encryption but with the wrong key type
  FAIL    - Cluster does not use secrets encryption

  resourceId - cluster name

`

export const handler = async (args: EksInterface) => {
  const scanner = new Eks({ ...args, rule })

  await scanner.start()
  scanner.output()
  return scanner.audits
}
