import { AWSScannerCliArgsInterface } from 'cloud-search'
import PublicAccessBlocks from './publicAccessBlocks'

const rule = 'BlockPublicPolicy'

export const command = `${rule} [args]`
export const desc = 'report on the block public policy toggle'

export const handler = async (args: AWSScannerCliArgsInterface) => {
  const scanner = new PublicAccessBlocks({
    profile: args.profile,
    resourceId: args.resourceId,
    domain: args.domain,
    region: args.region,
    rule,
  })
  await scanner.start()
  await scanner.output()
}
