import { PublicAccessBlocks } from './publicAccessBlocks'

export const command = 'PublicAccessBlocks [args]'
export const desc = 'report on all four s3 public access blocks toggles'

export const handler = async (args: AWSScannerInterface) => {
  const blockPublicAcls = new PublicAccessBlocks({
    region: args.region,
    profile: args.profile,
    resourceId: args.resourceId,
    verbosity: args.verbosity,
    rule: 'BlockPublicAcls',
  })
  await blockPublicAcls.start()

  const blockPublicPolicy = new PublicAccessBlocks({
    region: args.region,
    profile: args.profile,
    resourceId: args.resourceId,
    verbosity: args.verbosity,
    rule: 'BlockPublicPolicy',
  })
  await blockPublicPolicy.start()

  const ignorePublicAcls = new PublicAccessBlocks({
    region: args.region,
    profile: args.profile,
    resourceId: args.resourceId,
    verbosity: args.verbosity,
    rule: 'IgnorePublicAcls',
  })
  await ignorePublicAcls.start()

  const restrictPublicBuckets = new PublicAccessBlocks({
    region: args.region,
    profile: args.profile,
    resourceId: args.resourceId,
    verbosity: args.verbosity,
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

  restrictPublicBuckets.audits = audits

  restrictPublicBuckets.output()
  return audits
}
