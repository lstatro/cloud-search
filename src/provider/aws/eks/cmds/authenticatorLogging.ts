import { Eks, EksInterface } from './eks'

const rule = 'AuthenticatorLogging'

export const command = `${rule} [args]`

export const desc = `EKS Clusters should have authenticator logging enabled

  OK      - Cluster has authenticator logging enabled
  UNKNOWN - Unable to determine if cluster has authenticator logging enabled
  FAIL    - Cluster does not have authenticator logging enabled

  resourceId - cluster name

`

export const handler = async (args: EksInterface) => {
  const scanner = new Eks({ ...args, rule })

  await scanner.start()
  scanner.output()
  return scanner.audits
}
