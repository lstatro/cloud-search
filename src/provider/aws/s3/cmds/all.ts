import PublicAccessBlocks from './publicAccessBlocks'
import toTerminal from '../../../../lib/toTerminal'
import { AuditResultInterface, AWSScannerCliArgsInterface } from 'cloud-scan'

export const command = 'PublicAccessBlocks [args]'
export const desc = 'report on all four s3 public access blocks toggles'

export const handler = async (args: AWSScannerCliArgsInterface) => {
  const blockPublicAcls = new PublicAccessBlocks({
    region: args.region,
    profile: args.profile,
    resourceId: args.resourceId,
    domain: args.domain,
    rule: 'BlockPublicAcls',
  })
  await blockPublicAcls.start()

  const blockPublicPolicy = new PublicAccessBlocks({
    region: args.region,
    profile: args.profile,
    resourceId: args.resourceId,
    domain: args.domain,
    rule: 'BlockPublicPolicy',
  })
  await blockPublicPolicy.start()

  const ignorePublicAcls = new PublicAccessBlocks({
    region: args.region,
    profile: args.profile,
    resourceId: args.resourceId,
    domain: args.domain,
    rule: 'IgnorePublicAcls',
  })
  await ignorePublicAcls.start()

  const restrictPublicBuckets = new PublicAccessBlocks({
    region: args.region,
    profile: args.profile,
    resourceId: args.resourceId,
    domain: args.domain,
    rule: 'RestrictPublicBuckets',
  })
  await restrictPublicBuckets.start()

  let audits: AuditResultInterface[] = []

  audits = [
    ...blockPublicAcls.audits,
    ...blockPublicPolicy.audits,
    ...ignorePublicAcls.audits,
    ...restrictPublicBuckets.audits,
  ]

  toTerminal(audits)
}
