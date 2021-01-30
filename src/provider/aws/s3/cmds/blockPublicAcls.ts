import { AWSScannerCliArgsInterface } from '@lstatro/cloud-search'
import { PublicAccessBlocks } from './publicAccessBlocks'

const rule = 'BlockPublicAcls'

export const command = `${rule} [args]`
export const desc = `report on the block public acl toggle

  OK      - BlockPublicAcls set to true
  UNKNOWN - BlockPublicAcls state us unknown
  FAIL    - BlockPublicAcls set to false

  resource: bucket name

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
