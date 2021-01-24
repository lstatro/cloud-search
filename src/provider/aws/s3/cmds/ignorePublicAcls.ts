import { PublicAccessBlocks } from './publicAccessBlocks'

const rule = 'IgnorePublicAcls'

export const command = `${rule} [args]`
export const desc = `report the ignore public ACLs toggle

  OK      - IgnorePublicAcls set to true
  UNKNOWN - IgnorePublicAcls state us unknown
  FAIL    - IgnorePublicAcls set to false

  resourceId: bucket name

`

export const handler = async (args: AWSScannerInterface) => {
  const scanner = new PublicAccessBlocks({
    ...args,
    rule,
  })
  await scanner.start()
  scanner.output()
  return scanner.audits
}
