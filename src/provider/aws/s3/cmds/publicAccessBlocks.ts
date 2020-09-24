import BlockPublicAcls from './blockPublicAcls'
import { Scanner as BlockPublicPolicy } from './blockPublicPolicy'
import { Scanner as IgnorePublicAcls } from './ignorePublicAcls'
import { Scanner as RestrictPublicBuckets } from './restrictPublicBuckets'
import toTerminal from '../../../../lib/toTerminal'
import { AuditResultInterface, AWSScannerCliArgsInterface } from 'cloud-scan'

const rule = 'publicAccessBlocks'

export const command = `${rule} [args]`
export const desc = 'report on the four s3 public access blocks toggles'

export const handler = async (args: AWSScannerCliArgsInterface) => {
  const { region, profile, resourceId } = args
  const blockPublicAcls = await new BlockPublicAcls({
    region: args.region,
    profile: args.profile,
    resourceId: args.resourceId,
    domain: args.domain,
  })
  await blockPublicAcls.start()

  const blockPublicPolicy = await new BlockPublicPolicy(
    region as string,
    profile as string,
    resourceId as string
  )
  await blockPublicPolicy.start()

  const ignorePublicAcls = await new IgnorePublicAcls(
    region as string,
    profile as string,
    resourceId as string
  )
  await ignorePublicAcls.start()

  const restrictPublicBuckets = await new RestrictPublicBuckets(
    region as string,
    profile as string,
    resourceId as string
  )
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
