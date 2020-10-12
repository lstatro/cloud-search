import { AWSScannerCliArgsInterface } from 'cloud-search'
import PublicAccessBlocks from './publicAccessBlocks'

const rule = 'IgnorePublicAcls'

export const command = `${rule} [args]`
export const desc = `report the ignore public ACLs toggle

  OK      - IgnorePublicAcls set to true
  UNKNOWN - IgnorePublicAcls state us unknown
  FAIL    - IgnorePublicAcls set to false

  resourceId: bucket name

`

export const handler = async (args: AWSScannerCliArgsInterface) => {
  const scanner = new PublicAccessBlocks({
    profile: args.profile,
    resourceId: args.resourceId,
    region: args.region,
    rule,
  })
  await scanner.start()
  scanner.output()
  return scanner.audits
}
