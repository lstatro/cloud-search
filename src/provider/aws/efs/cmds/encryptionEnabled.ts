import { CommandBuilder } from 'yargs'
import {
  AuditResultInterface,
  AWSScannerInterface,
} from '@lstatro/cloud-search'
import { AWS, keyTypeArg } from '../../../../lib/aws/AWS'
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
    const audit = this.getDefaultAuditObj({
      region,
      resource: resource.FileSystemId,
    })
    try {
      assert(
        resource.hasOwnProperty('Encrypted'),
        'encrypted attribute must exist for auditing to continue'
      )
      const isEncryptionEnabled = resource.Encrypted === true
      if (isEncryptionEnabled) {
        audit.state = 'OK'
      } else {
        audit.state = 'FAIL'
      }
    } catch (error) {
      /**
       * If a fault is encountered we still want to return an audit to the user.
       * We return an audit state of UNKNOWN if any fault is encountered during
       * the audit phase.
       */
      console.error('There was an issue auditing', error)
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
    const params: { FileSystemId?: string } = {}
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
