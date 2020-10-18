import { CommandBuilder } from 'yargs'
import { Volume } from 'aws-sdk/clients/ec2'
import { AuditResultInterface, AWSScannerInterface } from 'cloud-search'
import assert from 'assert'
import { AWS, keyTypeArg } from '../../../../../lib/aws/AWS'

const rule = 'VolumesEncrypted'

export const command = `${rule} [args]`

export const builder: CommandBuilder = {
  ...keyTypeArg,
}

export const desc = `Verifies that EBS volume are encrypted

  OK      - The volume is encrypted with the specified key
  UNKNOWN - unable to determine the volume's encryption state
  WARNING - the volume is encrypted, but not with the right key
  FAIL    - the volume is not encrypted

  resourceId - volume id (vol-xxxxxx)

`

export default class VolumesEncrypted extends AWS {
  audits: AuditResultInterface[] = []
  service = 'ebs'

  constructor(public params: AWSScannerInterface) {
    super({
      profile: params.profile,
      resourceId: params.resourceId,
      region: params.region,
      verbosity: params.verbosity,
      rule,
    })
    this.keyType = params.keyType || 'aws'
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
      assert(this.keyType, 'key type is required')
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
    resourceId,
  }: {
    region: string
    resourceId?: string
  }) => {
    const options = this.getOptions()
    options.region = region

    const volumes = await this.describeVolumes(region, resourceId)

    for (const volume of volumes) {
      this.audit({ resource: volume, region })
    }
  }
}

export const handler = async (args: AWSScannerInterface) => {
  const scanner = await new VolumesEncrypted({
    region: args.region,
    profile: args.profile,
    resourceId: args.resourceId,
    keyType: args.keyType,
    verbosity: args.verbosity,
  })
  await scanner.start()
  scanner.output()
  return scanner.audits
}
