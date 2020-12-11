import { Eks, EksInterface } from './eks'

const rule = 'ControllerManagerLogging'

export const command = `${rule} [args]`

export const desc = `EKS Clusters should have controller manager logging enabled

  OK      - Cluster has controller manager logging enabled
  UNKNOWN - Unable to determine if cluster has controller manager logging enabled
  FAIL    - Cluster does not have controller manager logging enabled

  resourceId - cluster name

`

export const handler = async (args: EksInterface) => {
  const scanner = new Eks({ ...args, rule })

  await scanner.start()
  scanner.output()
  return scanner.audits
}
