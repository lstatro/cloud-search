import { AWS, keyTypeArg } from '../../../../lib/aws/AWS'
import {
  AWSScannerInterface,
  AuditResultInterface,
} from '@lstatro/cloud-search'

import { TrailInfo } from 'aws-sdk/clients/cloudtrail'
import assert from 'assert'

const rule = 'TrailEncrypted'

export const builder = {
  ...keyTypeArg,
}

export const command = `${rule} [args]`

export const desc = `a cloudtrail trail must be configured for encryption

  OK      - The trail is encrypted
  WARNING - The trail is encrypted but with the wrong key type
  UNKNOWN - Unable to determine trail encryption
  FAIL    - The trail is not encrypted

  resource: trail name

`

export class TrailEncrypted extends AWS {
  audits: AuditResultInterface[] = []
  service = 'cloudtrail'
  global = false

  constructor(public params: AWSScannerInterface) {
    super({ ...params, rule })
  }

  async audit({ resource, region }: { resource: string; region: string }) {
    assert(this.keyType, 'key type is required')

    const options = this.getOptions()
    options.region = region

    const audit = this.getDefaultAuditObj({ resource, region })

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

  scan = async ({ resource, region }: { resource: string; region: string }) => {
    if (resource) {
      await this.audit({ resource: resource, region })
    } else {
      const options = this.getOptions()
      options.region = region

      const promise = new this.AWS.CloudTrail(options).listTrails().promise()
      const trails = await this.pager<TrailInfo>(promise, 'Trails')

      for (const trail of trails) {
        if (trail.HomeRegion === region) {
          assert(trail.TrailARN, 'trail does not have a ARN')
          await this.audit({ resource: trail.TrailARN, region })
        }
      }
    }
  }
}

export const handler = async (args: AWSScannerInterface) => {
  const scanner = new TrailEncrypted(args)

  await scanner.start()
  scanner.output()
  return scanner.audits
}
