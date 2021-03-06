import { AWSScannerCliArgsInterface } from '@lstatro/cloud-search'
import { PublicAccessBlocks } from './publicAccessBlocks'

const rule = 'BlockPublicPolicy'

export const command = `${rule} [args]`
export const desc = `report on the block public policy toggle

  OK      - BlockPublicPolicy set to true
  UNKNOWN - BlockPublicPolicy state us unknown
  FAIL    - BlockPublicPolicy set to false

  resourceId: bucket name

`

export const handler = async (args: AWSScannerCliArgsInterface) => {
  const scanner = new PublicAccessBlocks({
    ...args,
    rule,
  })
  await scanner.start()
  scanner.output()
  return scanner.audits
}
