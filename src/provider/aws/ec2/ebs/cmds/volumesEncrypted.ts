import { EC2, KMS } from 'aws-sdk'
import { CommandBuilder } from 'yargs'
import { Volume } from 'aws-sdk/clients/ec2'
import {
  AuditResultInterface,
  AWSScannerCliArgsInterface,
  AWSScannerInterface,
  AWSClientOptionsInterface,
} from 'cloud-search'
import assert from 'assert'
import AWS from '../../../../../lib/aws/AWS'

const rule = 'VolumesEncrypted'

type VolumeHandlerFunctions = (
  volume: Volume,
  audit: AuditResultInterface
) => void

export const command = `${rule} [args]`
export const desc = 'Verifies that EBS volume are encrypted'

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

export interface VolumesEncryptedInterface extends AWSScannerInterface {
  KeyArn?: string
  keyType: 'aws' | 'cmk'
}

export default class VolumesEncrypted extends AWS {
  audits: AuditResultInterface[] = []
  service = 'ebs'
  cmks: string[] = []
  KeyArn?: string
  keyType: string

  constructor(public params: VolumesEncryptedInterface) {
    super({
      profile: params.profile,
      resourceId: params.resourceId,
      domain: params.domain,
      region: params.region,
      rule,
    })
    this.KeyArn = params.KeyArn
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

  getCustomerMangedKeys = async (options: AWSClientOptionsInterface) => {
    if (typeof this.KeyArn === 'string') {
      this.cmks.push(this.KeyArn)
    } else {
      const kms = new KMS(options)
      let marker: string | undefined
      do {
        const listKeys = await kms
          .listKeys({
            Marker: marker,
          })
          .promise()
        marker = listKeys.NextMarker
        assert(listKeys.Keys, 'key has no keys')
        for (const key of listKeys.Keys) {
          assert(key.KeyArn, 'key has no id')
          this.cmks.push(key.KeyArn)
        }
      } while (marker)
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

    const ec2 = new EC2(options)

    let nextToken: string | undefined

    try {
      await this.getCustomerMangedKeys(options)
      do {
        const describeVolumes = await ec2
          .describeVolumes({
            NextToken: nextToken,
            VolumeIds: resourceId ? [resourceId] : undefined,
          })
          .promise()
        nextToken = describeVolumes.NextToken

        if (describeVolumes.Volumes) {
          for (const volume of describeVolumes.Volumes) {
            this.audit(volume, region)
          }
        }
      } while (nextToken)
    } catch (err) {
      this.audits.push({
        provider: 'aws',
        comment: `unable to audit resource ${err.code} - ${err.message}`,
        physicalId: resourceId,
        service: this.service,
        rule,
        region: region,
        state: 'UNKNOWN',
        profile: this.profile,
        time: new Date().toISOString(),
      })
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
    KeyArn: args.KeyArn,
    keyType: args.keyType,
  })
  await scanner.start()
  scanner.output()
  return scanner.audits
}
