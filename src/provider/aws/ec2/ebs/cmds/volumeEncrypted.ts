import { CommandBuilder } from 'yargs'
import { Volume } from 'aws-sdk/clients/ec2'
import {
  AuditResultInterface,
  AWSScannerInterface,
} from '@lstatro/cloud-search'
import assert from 'assert'
import { AWS, keyTypeArg } from '../../../../../lib/aws/AWS'

const rule = 'VolumesEncrypted'

export const command = `${rule} [args]`

export const builder: CommandBuilder = {
  ...keyTypeArg,
}

export const desc = `EBS volumes should be encrypted at rest

  OK      - The volume is encrypted with the specified key
  UNKNOWN - Unable to determine the volume's encryption state
  WARNING - The volume is encrypted, but not with the right key type
  FAIL    - The volume is not encrypted

  resourceId - snapshot id

`

export default class VolumesEncrypted extends AWS {
  audits: AuditResultInterface[] = []
  service = 'ebs'

  constructor(public params: AWSScannerInterface) {
    super({ ...params, rule })
  }

  async audit({ resource, region }: { resource: Volume; region: string }) {
    assert(resource.VolumeId, 'volume does not have an ID')

    const audit = this.getDefaultAuditObj({
      resource: resource.VolumeId,
      region: region,
    })

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

    const promise = new this.AWS.EC2(options)
      .describeVolumes({
        VolumeIds: resourceId ? [resourceId] : undefined,
      })
      .promise()

    const volumes = await this.pager<Volume>(promise, 'Volumes')

    for (const volume of volumes) {
      await this.audit({ resource: volume, region })
    }
  }
}

export const handler = async (args: AWSScannerInterface) => {
  const scanner = new VolumesEncrypted(args)
  await scanner.start()
  scanner.output()
  return scanner.audits
}
