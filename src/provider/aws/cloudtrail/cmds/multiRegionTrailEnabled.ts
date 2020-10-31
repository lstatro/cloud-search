import { AuditResultInterface, AWSScannerInterface } from 'cloud-search'
import assert from 'assert'

import { AWS } from '../../../../lib/aws/AWS'
import { TrailInfo } from 'aws-sdk/clients/cloudtrail'

const rule = 'MultiRegionTrailEnabled'

export const command = `${rule} [args]`

export const desc = `a cloudtrail trail's multi-region flag is set to true and the trail is logging

  OK      - This trail has its multi-region flag set to true and is actively logging
  UNKNOWN - Unable to determine if a multi-region trail exists or if it is enabled
  WARNING - This trail has its multi-region flag set to true, but is not logging
  FAIL    - This trail has its multi-region flag set to false, or is undefined

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
    super({ ...params, rule })
  }

  async audit({ resource, region }: { resource: string; region: string }) {
    const options = this.getOptions()
    options.region = region

    const audit = this.getDefaultAuditObj({ resource, region })

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
      const options = this.getOptions()
      options.region = region

      const trails = await this.pager<TrailInfo>(
        new this.AWS.CloudTrail(this.options).listTrails().promise(),
        'Trails'
      )

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
  const scanner = new MultiRegionTrailEnabled(args)

  await scanner.start()
  scanner.output()
  return scanner.audits
}
