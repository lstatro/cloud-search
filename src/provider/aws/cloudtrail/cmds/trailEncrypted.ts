import { AuditResultInterface, AWSScannerInterface } from 'cloud-search'
import assert from 'assert'

import { AWS, keyTypeArg } from '../../../../lib/aws/AWS'

const rule = 'TrailEncrypted'

export const builder = {
  ...keyTypeArg,
}

export const command = `${rule} [args]`

export const desc = `a cloudtrail trail must be configured for encryption

  OK      - the trail is encrypted
  WARNING - the trail is encrypted but with the wrong key type
  UNKNOWN - unable to determine trail encryption
  FAIL    - the trail is not encrypted

  resourceId: trail name

`

export default class TrailEncrypted extends AWS {
  audits: AuditResultInterface[] = []
  service = 'cloudtrail'
  global = false

  constructor(public params: AWSScannerInterface) {
    super({
      profile: params.profile,
      region: params.region,
      verbosity: params.verbosity,
      resourceId: params.resourceId,
      keyType: params.keyType,
      rule,
    })
  }

  async audit({ resource, region }: { resource: string; region: string }) {
    assert(this.keyType, 'key type is required')

    const options = this.getOptions()
    options.region = region

    const audit: AuditResultInterface = {
      provider: 'aws',
      physicalId: resource,
      service: this.service,
      rule: this.rule,
      region: region,
      state: 'UNKNOWN',
      profile: this.profile,
      time: new Date().toISOString(),
    }

    const cloudtrail = new this.AWS.CloudTrail(options)
    const getTrail = await cloudtrail
      .getTrail({
        Name: resource,
      })
      .promise()

    if (getTrail.Trail) {
      if (getTrail.Trail.KmsKeyId) {
        audit.state = await this.isKeyTrusted(
          getTrail.Trail.KmsKeyId,
          this.keyType,
          region
        )
      } else {
        audit.state = 'FAIL'
      }
    }

    this.audits.push(audit)
  }

  scan = async ({
    resourceId,
    region,
  }: {
    resourceId: string
    region: string
  }) => {
    if (resourceId) {
      await this.audit({ resource: resourceId, region })
    } else {
      const trails = await this.listTrails(region)
      for (const trail of trails) {
        assert(trail.TrailARN, 'trail does not have a ARN')
        await this.audit({ resource: trail.TrailARN, region })
      }
    }
  }
}

export const handler = async (args: AWSScannerInterface) => {
  const scanner = new TrailEncrypted({
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