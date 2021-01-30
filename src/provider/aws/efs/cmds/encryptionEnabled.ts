import { AWS, keyTypeArg } from '../../../../lib/aws/AWS'
import {
  AWSScannerInterface,
  AuditResultInterface,
} from '@lstatro/cloud-search'

import { CommandBuilder } from 'yargs'
import { FileSystemDescription } from 'aws-sdk/clients/efs'
import assert from 'assert'

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

  resource - FileSystemId

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
    const audit = this.getDefaultAuditObj({
      region,
      resource: resource.FileSystemId,
    })
    if (resource.KmsKeyId) {
      assert(
        this.keyType,
        'Key type is required arguement for isKeyTrusted check'
      )
      audit.state = await this.isKeyTrusted(
        resource.KmsKeyId,
        this.keyType,
        region
      )
    } else {
      audit.state = 'FAIL'
    }

    this.audits.push(audit)
  }
  scan = async ({ region, resource }: { region: string; resource: string }) => {
    const params: { FileSystemId?: string } = {}
    if (resource) {
      params.FileSystemId = resource
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
    for (const fileSystem of fileSystems) {
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
