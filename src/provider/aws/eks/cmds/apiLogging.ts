import { Eks, EksInterface } from './eks'

const rule = 'ApiLogging'

export const command = `${rule} [args]`

export const desc = `EKS Clusters should have API logging enabled

  OK      - Cluster has API logging enabled
  UNKNOWN - Unable to determine if cluster has API logging enabled
  FAIL    - Cluster does not have API logging enabled

  resource - cluster name

`

export const handler = async (args: EksInterface) => {
  const scanner = new Eks({ ...args, rule })

  await scanner.start()
  scanner.output()
  return scanner.audits
}
