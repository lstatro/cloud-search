import { AuditResultInterface, AWSScannerInterface } from 'cloud-search'
import assert from 'assert'

import { AWS } from '../../../../lib/aws/AWS'
import { CloudTrail } from 'aws-sdk'
import { TrailInfo } from 'aws-sdk/clients/cloudtrail'

const rule = 'TrailEvents'

export const command = `${rule} [args]`

export const desc = `a cloudtrail configuration must include:
  - s3 object logging
  - lambda function invocations
  - include management events
  - capture both read and write api calls

  OK      - This trail has all of the desired configuration targets
  WARNING - This trail has all of the desired configuration targets, but is not actively logging
  UNKNOWN - Unable to determine if the trail is configured correctly
  FAIL    - The trail is missing one or all of the desired configuration targets

  resourceId: trail name

`

export default class TrailEvents extends AWS {
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
      .getEventSelectors({
        TrailName: resource,
      })
      .promise()

    let hasConfig = false
    if (getTrail.EventSelectors) {
      for (const selector of getTrail.EventSelectors) {
        const readWriteType = this.hasReadWriteType(selector)

        const s3Resource = this.hasDataResource(
          selector,
          'AWS::S3::Object',
          'arn:aws:s3'
        )

        const lambdaResource = this.hasDataResource(
          selector,
          'AWS::Lambda::Function',
          'arn:aws:lambda'
        )

        const hasMgmtEvents = this.hasMgmtEvents(selector)

        if (readWriteType && s3Resource && lambdaResource && hasMgmtEvents) {
          hasConfig = true
        }
      }
    }

    if (hasConfig === true) {
      const getTrailStatus = await cloudtrail
        .getTrailStatus({
          Name: resource,
        })
        .promise()
      if (getTrailStatus.IsLogging === true) {
        audit.state = 'OK'
      } else {
        audit.state = 'WARNING'
      }
    } else {
      audit.state = 'FAIL'
    }

    this.audits.push(audit)
  }

  hasMgmtEvents = (selector: CloudTrail.EventSelector) => {
    let found = false
    if (selector.IncludeManagementEvents === true) {
      found = true
    }
    return found
  }

  hasReadWriteType = (selector: CloudTrail.EventSelector) => {
    let found = false
    if (selector.ReadWriteType === 'All') {
      found = true
    }
    return found
  }

  hasDataResource = (
    selector: CloudTrail.EventSelector,
    type: 'AWS::S3::Object' | 'AWS::Lambda::Function',
    value: 'arn:aws:s3' | 'arn:aws:lambda'
  ) => {
    let found = false
    if (selector.DataResources) {
      for (const resource of selector.DataResources) {
        if (resource.Type === type) {
          if (resource.Values) {
            if (resource.Values.includes(value)) {
              found = true
            }
          }
        }
      }
    }
    return found
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
  const scanner = new TrailEvents(args)

  await scanner.start()
  scanner.output()
  return scanner.audits
}
