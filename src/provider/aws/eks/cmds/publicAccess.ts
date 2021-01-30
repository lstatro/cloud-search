import { Eks, EksInterface } from './eks'

const rule = 'PublicAccess'

export const command = `${rule} [args]`

export const desc = `EKS Clusters should not be public

  OK      - Cluster is not public
  UNKNOWN - Unable to determine if cluster is public
  FAIL    - Cluster is public

  resource - cluster name

`

export const handler = async (args: EksInterface) => {
  const scanner = new Eks({ ...args, rule })

  await scanner.start()
  scanner.output()
  return scanner.audits
}
