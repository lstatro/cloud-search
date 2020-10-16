import { AWSScannerCliArgsInterface } from 'cloud-search'
import PublicAccessBlocks from './publicAccessBlocks'

const rule = 'BlockPublicAcls'

export const command = `${rule} [args]`
export const desc = `report on the block public acl toggle

  OK      - BlockPublicAcls set to true
  UNKNOWN - BlockPublicAcls state us unknown
  FAIL    - BlockPublicAcls set to false

  resourceId: bucket name

`

export const handler = async (args: AWSScannerCliArgsInterface) => {
  const scanner = new PublicAccessBlocks({
    profile: args.profile,
    resourceId: args.resourceId,
    region: args.region,
    verbosity: args.verbosity,
    rule,
  })
  await scanner.start()
  scanner.output()
  return scanner.audits
}
