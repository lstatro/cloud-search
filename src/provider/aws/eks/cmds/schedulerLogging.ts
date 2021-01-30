import { Eks, EksInterface } from './eks'

const rule = 'SchedulerLogging'

export const command = `${rule} [args]`

export const desc = `EKS Clusters should have scheduler logging enabled

  OK      - Cluster has scheduler logging enabled
  UNKNOWN - Unable to determine if cluster has scheduler logging enabled
  FAIL    - Cluster does not have scheduler logging enabled

  resource - cluster name

`

export const handler = async (args: EksInterface) => {
  const scanner = new Eks({ ...args, rule })

  await scanner.start()
  scanner.output()
  return scanner.audits
}
