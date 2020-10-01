import { CommandBuilder } from 'yargs'
import { Volume } from 'aws-sdk/clients/ec2'
import {
  AuditResultInterface,
  AWSScannerCliArgsInterface,
  AWSScannerInterface,
} from 'cloud-search'
import assert from 'assert'
import AWS from '../../../../../lib/aws/AWS'

const rule = 'VolumesEncrypted'

type VolumeHandlerFunctions = (
  volume: Volume,
  audit: AuditResultInterface
) => void

export const command = `${rule} [args]`
export const builder: CommandBuilder = {
  keyType: {
    alias: 't',
    describe: 'the AWS key type',
    type: 'string',
    default: 'aws',
    choices: ['aws', 'cmk'],
  },
  keyArn: {
    alias: 'a',
    describe: 'a KMS key arn',
    type: 'string',
  },
}

export const desc = `Verifies that EBS volume are encrypted

  OK      - The volume is encrypted with the specified key
  UNKNOWN - unable to determine the volume's encryption state
  WARNING - the volume is encrypted, but not with the right key
  FAIL    - the volume is not encrypted

`

export interface VolumesEncryptedInterface extends AWSScannerInterface {
  keyArn?: string
  keyType: 'aws' | 'cmk'
}

export default class VolumesEncrypted extends AWS {
  audits: AuditResultInterface[] = []
  service = 'ebs'
  cmks: string[] = []
  keyArn?: string
  keyType: string

  constructor(public params: VolumesEncryptedInterface) {
    super({
      profile: params.profile,
      resourceId: params.resourceId,
      domain: params.domain,
      region: params.region,
      rule,
    })
    this.keyArn = params.keyArn
    this.keyType = params.keyType
  }

  handleCmkType = (volume: Volume, audit: AuditResultInterface) => {
    if (volume.Encrypted) {
      audit.state = 'WARNING'
      audit.comment = 'encrypted but with an unknown key'
      if (volume.KmsKeyId) {
        if (this.cmks.includes(volume.KmsKeyId)) {
          audit.state = 'OK'
          audit.comment = 'encrypted with a known key'
        }
      }
    } else {
      audit.state = 'FAIL'
    }
  }

  handleAwsType = (volume: Volume, audit: AuditResultInterface) => {
    if (volume.Encrypted === true) {
      audit.state = 'OK'
      audit.comment = 'encrypted with aws account ebs key'
      if (this.keyArn) {
        if (this.keyArn !== volume.KmsKeyId) {
          audit.state = 'WARNING'
        }
      }
    } else {
      audit.state = 'FAIL'
    }
  }

  async audit(volume: Volume, region: string) {
    const audit: AuditResultInterface = {
      provider: 'aws',
      physicalId: volume.VolumeId,
      service: this.service,
      rule,
      region: region,
      state: 'UNKNOWN',
      profile: this.profile,
      time: new Date().toISOString(),
    }

    const types: { [key: string]: VolumeHandlerFunctions } = {
      aws: this.handleAwsType,
      cmk: this.handleCmkType,
    }
    types[this.keyType](volume, audit)
    this.audits.push(audit)
  }

  getCustomerMangedKeys = async (region: string) => {
    if (typeof this.keyArn === 'string') {
      this.cmks.push(this.keyArn)
    } else {
      const options = this.getOptions()
      options.region = region

      const kms = new this.AWS.KMS(options)

      const keys = await this.listKeys(region)

      for (const key of keys) {
        assert(key.KeyId, 'key has no id')
        assert(key.KeyArn, 'key has no ARN')
        const describeKey = await kms
          .describeKey({
            KeyId: key.KeyId,
          })
          .promise()
        assert(describeKey.KeyMetadata, 'key missing metadata')
        if (describeKey.KeyMetadata.KeyManager === 'CUSTOMER') {
          this.cmks.push(key.KeyArn)
        }
      }
    }
  }

  scan = async ({
    region,
    resourceId,
  }: {
    region: string
    resourceId?: string
  }) => {
    const options = this.getOptions()
    options.region = region

    await this.getCustomerMangedKeys(region)

    const volumes = await this.describeVolumes(region, resourceId)

    for (const volume of volumes) {
      this.audit(volume, region)
    }
  }
}

export interface VolumesEncryptedCliInterface
  extends VolumesEncryptedInterface,
    AWSScannerCliArgsInterface {}

export const handler = async (args: VolumesEncryptedCliInterface) => {
  const scanner = await new VolumesEncrypted({
    region: args.region,
    profile: args.profile,
    resourceId: args.resourceId,
    domain: args.domain,
    keyArn: args.keyArn,
    keyType: args.keyType,
  })
  await scanner.start()
  scanner.output()
  return scanner.audits
}
