import { CommandBuilder } from 'yargs'
import {
  AuditResultInterface,
  AWSScannerInterface,
} from '@lstatro/cloud-search'
import { AWS, keyTypeArg } from '../../../../lib/aws/AWS'
import { FileSystemDescriptions } from 'aws-sdk/clients/efs'
// import assert from 'assert'

const rule = 'EncryptionEnabled'

export const command = `${rule} [args]`
export const builder: CommandBuilder = {
  ...keyTypeArg,
}
export const desc = `EFS must be encrypted

  OK      - EFS is encrypted
  UNKNOWN - Unable to determine EFS encryption
  WARNING - EFS encrypted but not with the specified key type
  FAIL    - EFS is not encrypted

  resourceId - FileSystemId

`

export class EFSEncryption extends AWS {
  audits: AuditResultInterface[] = []
  service = 'efs'
  global = false

  constructor(public params: AWSScannerInterface) {
    super({ ...params, rule })
  }
  async audit({ region }: { region: string }) {
    console.log('audit')
    const audit = this.getDefaultAuditObj({ region })
    this.audits.push()
  }
  scan = async ({ region }: { region: string }) => {
    const options = this.getOptions()
    options.region = region
    const promise = new this.AWS.EFS(options).describeFileSystems().promise()
    const fileSystems = await this.pager<FileSystemDescriptions>(
      promise,
      'FileSystems'
    )
    console.log('scan')
    console.log('these are fileSystems ..', fileSystems)
    // await this.audit({ region })
  }
}

export const handler = async (args: AWSScannerInterface) => {
  const scanner = new EFSEncryption(args)

  await scanner.start()
  scanner.output()
  return scanner.audits
}
