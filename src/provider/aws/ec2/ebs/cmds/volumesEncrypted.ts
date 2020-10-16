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

  resourceId - volume id (vol-xxxxxx)

`

export interface VolumesEncryptedInterface extends AWSScannerInterface {
  keyArn?: string
  keyType: 'aws' | 'cmk'
}

export default class VolumesEncrypted extends AWS {
  audits: AuditResultInterface[] = []
  service = 'ebs'
  keyArn?: string
  keyType: 'aws' | 'cmk'

  constructor(public params: VolumesEncryptedInterface) {
    super({
      profile: params.profile,
      resourceId: params.resourceId,
      region: params.region,
      verbosity: params.verbosity,
      rule,
    })
    this.keyArn = params.keyArn
    this.keyType = params.keyType
  }

  async audit({ resource, region }: { resource: Volume; region: string }) {
    assert(resource.VolumeId, 'volume does not have an ID')
    const audit: AuditResultInterface = {
      provider: 'aws',
      physicalId: resource.VolumeId,
      service: this.service,
      rule,
      region: region,
      state: 'UNKNOWN',
      profile: this.profile,
      time: new Date().toISOString(),
    }

    if (resource.KmsKeyId) {
      assert(
        resource.Encrypted === true,
        'key detected, but volume reports as not encrypted'
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

  scan = async ({
    region,
    resource,
  }: {
    region: string
    resource?: string
  }) => {
    const options = this.getOptions()
    options.region = region

    const volumes = await this.describeVolumes(region, resource)

    for (const volume of volumes) {
      this.audit({ resource: volume, region })
    }
  }
}

export interface VolumesEncryptedCliInterface
  extends VolumesEncryptedInterface,
    AWSScannerCliArgsInterface {}

export const handler = async (args: VolumesEncryptedInterface) => {
  const scanner = await new VolumesEncrypted({
    region: args.region,
    profile: args.profile,
    resourceId: args.resourceId,
    keyArn: args.keyArn,
    keyType: args.keyType,
    verbosity: args.verbosity,
  })
  await scanner.start()
  scanner.output()
  return scanner.audits
}
