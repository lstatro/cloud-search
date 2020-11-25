import {
  AuditResultInterface,
  AWSScannerInterface,
} from '@lstatro/cloud-search'
import { Bucket } from 'aws-sdk/clients/s3'
import { AWS } from '../../../../lib/aws/AWS'
import assert from 'assert'
const rule = 'BucketVersioningEnabled'

export const command = `${rule} [args]`

export const desc = `S3 Buckets should have versioning enabled.

  OK      - Versioning is enabled
  UNKNOWN - Unable to determine if versioning is enabled
  FAIL    - Versioning is not enabled

  resourceId: BucketName

`

export default class BucketVersioningEnabled extends AWS {
  audits: AuditResultInterface[] = []
  service = 's3'
  global = true

  constructor(public params: AWSScannerInterface) {
    super({ ...params, rule })
  }

  async audit({ resource, region }: { resource: string; region: string }) {
    const options = this.getOptions()
    const s3 = new this.AWS.S3(options)
    options.region = region
    const audit = this.getDefaultAuditObj({
      resource: resource,
      region,
    })
    const getBucketVersioning = await s3
      .getBucketVersioning({ Bucket: resource })
      .promise()
    const isVersioning = getBucketVersioning.Status === 'Enabled'
    if (isVersioning) {
      audit.state = 'OK'
    } else {
      audit.state = 'FAIL'
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

      const promise = new this.AWS.S3(options).listBuckets().promise()
      const buckets = await this.pager<Bucket>(promise, 'Buckets')

      for (const bucket of buckets) {
        assert(bucket.Name, 'the bucket must have a name')
        await this.audit({ resource: bucket.Name, region })
      }
    }
  }
}

export const handler = async (args: AWSScannerInterface) => {
  const scanner = new BucketVersioningEnabled(args)
  await scanner.start()
  scanner.output()
  return scanner.audits
}
