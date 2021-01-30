import { Eks, EksInterface } from './eks'

const rule = 'AuditLogging'

export const command = `${rule} [args]`

export const desc = `EKS Clusters should have audit logging enabled

  OK      - Cluster has audit logging enabled
  UNKNOWN - Unable to determine if cluster has audit logging enabled
  FAIL    - Cluster does not have audit logging enabled

  resource - cluster name

`

export const handler = async (args: EksInterface) => {
  const scanner = new Eks({ ...args, rule })

  await scanner.start()
  scanner.output()
  return scanner.audits
}
