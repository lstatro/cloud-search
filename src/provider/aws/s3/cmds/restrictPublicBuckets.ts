import { AWSScannerCliArgsInterface } from 'cloud-search'
import PublicAccessBlocks from './publicAccessBlocks'

const rule = 'RestrictPublicBuckets'

export const command = `${rule} [args]`
export const desc = `report on the restrict public access toggle

  OK      - RestrictPublicBuckets set to true
  UNKNOWN - RestrictPublicBuckets state us unknown
  FAIL    - RestrictPublicBuckets set to false

`

export const handler = async (args: AWSScannerCliArgsInterface) => {
  const scanner = new PublicAccessBlocks({
    profile: args.profile,
    resourceId: args.resourceId,
    domain: args.domain,
    region: args.region,
    rule,
  })
  await scanner.start()
  scanner.output()
  return scanner.audits
}
