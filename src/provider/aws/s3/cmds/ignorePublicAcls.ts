import { AWSScannerCliArgsInterface } from 'cloud-scan'
import toTerminal from '../../../../lib/toTerminal'
import PublicAccessBlocks from './publicAccessBlocks'

const rule = 'IgnorePublicAcls'

export const command = `${rule} [args]`
export const desc = 'report the ignore public ACLs toggle'

export const handler = async (args: AWSScannerCliArgsInterface) => {
  const scanner = new PublicAccessBlocks({
    profile: args.profile,
    resourceId: args.resourceId,
    domain: args.domain,
    region: args.region,
    rule,
  })
  await scanner.start()
  toTerminal(scanner.audits)
}
