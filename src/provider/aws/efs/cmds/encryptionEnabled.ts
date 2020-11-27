import { CommandBuilder } from 'yargs'
import {
  AuditResultInterface,
  AWSScannerInterface,
} from '@lstatro/cloud-search'
import { AWS, keyTypeArg } from '../../../../lib/aws/AWS'
import { FileSystemDescription } from 'aws-sdk/clients/efs'
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
  async audit({
    region,
    resource,
  }: {
    region: string
    resource: FileSystemDescription
  }) {
    console.log('audit')

    const audit = this.getDefaultAuditObj({
      region,
      resource: resource.FileSystemId,
    })
    const isEncryptionEnabled = resource.Encrypted === true
    if (isEncryptionEnabled) {
      audit.state = 'OK'
    } else {
      audit.state = 'FAIL'
    }
    this.audits.push(audit)
  }
  scan = async ({
    region,
    resourceId,
  }: {
    region: string
    resourceId: string
  }) => {
    let params = {
      FileSystemId: '',
    }
    if (resourceId) {
      params.FileSystemId = resourceId
    }
    const options = this.getOptions()
    options.region = region
    const promise = new this.AWS.EFS(options)
      .describeFileSystems(params)
      .promise()
    const fileSystems = await this.pager<FileSystemDescription>(
      promise,
      'FileSystems'
    )
    console.log('scan')
    console.log('these are fileSystems ..', fileSystems)
    for (const fileSystem of fileSystems) {
      console.log('this is fileSystem...', fileSystem)
      await this.audit({ region, resource: fileSystem })
    }
  }
}

export const handler = async (args: AWSScannerInterface) => {
  const scanner = new EFSEncryption(args)

  await scanner.start()
  scanner.output()
  return scanner.audits
}
