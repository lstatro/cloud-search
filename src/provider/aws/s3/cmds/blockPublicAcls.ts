import { AWSScannerCliArgsInterface } from 'cloud-search'
import PublicAccessBlocks from './publicAccessBlocks'

const rule = 'BlockPublicAcls'

export const command = `${rule} [args]`
export const desc = 'report on the block public acl toggle'

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
