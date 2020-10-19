import { AuditResultInterface, AWSScannerInterface } from 'cloud-search'
import assert from 'assert'

import { AWS } from '../../../../lib/aws/AWS'

const rule = 'MultiRegionTrailEnabled'

export const command = `${rule} [args]`

export const desc = `a cloudtrail trail's multi-region flag is set to true and the trail is logging

  OK      - this trail has its multi-region flag set to true and is actively logging
  UNKNOWN - unable to determine if a multi-region trail exists or if it is enabled
  WARNING - this trail has its multi-region flag set to true, but is not logging
  FAIL    - this trail has its multi-region flag set to false, or is undefined

  resourceId: trail ARN

  note: multi-regional trails are global.  Meaning, we only need to search one region to find a multi-region
        trail.  To combat this we validate the trail returned in a scan lives in the region we made the api 
        call too.  If it does not, it is ignored.  This ensures that we we catch a multi-region trail we also
        catch the real home region.

`

export default class MultiRegionTrailEnabled extends AWS {
  audits: AuditResultInterface[] = []
  service = 'cloudtrail'
  global = false

  constructor(public params: AWSScannerInterface) {
    super({
      profile: params.profile,
      region: params.region,
      verbosity: params.verbosity,
      resourceId: params.resourceId,
      rule,
    })
  }

  async audit({ resource, region }: { resource: string; region: string }) {
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

    const getTrailStatus = await cloudtrail
      .getTrailStatus({
        Name: resource,
      })
      .promise()

    if (getTrail.Trail) {
      if (getTrail.Trail.IsMultiRegionTrail === true) {
        audit.state = 'WARNING'
        if (getTrailStatus.IsLogging === true) {
          audit.state = 'OK'
        }
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
  const scanner = new MultiRegionTrailEnabled({
    region: args.region,
    profile: args.profile,
    resourceId: args.resourceId,
    verbosity: args.verbosity,
  })

  await scanner.start()
  scanner.output()
  return scanner.audits
}
