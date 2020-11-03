import { Bucket, GetPublicAccessBlockOutput } from 'aws-sdk/clients/s3'
import { AWSScannerInterface } from 'cloud-search'
import assert from 'assert'
import { AWS } from '../../../../lib/aws/AWS'

interface PublicAccessBlocksInterface extends AWSScannerInterface {
  rule: string
}

export default class PublicAccessBlocks extends AWS {
  service = 's3'
  global = true

  constructor(public params: PublicAccessBlocksInterface) {
    super(params)
  }

  async audit({ resource }: { resource: string }) {
    const options = this.getOptions()
    const s3 = new this.AWS.S3(options)

    try {
      const getPublicAccessBlock = await s3
        .getPublicAccessBlock({ Bucket: resource })
        .promise()
      assert(getPublicAccessBlock, 'unable to locate bucket')
      this.validate(getPublicAccessBlock, resource)
    } catch (err) {
      const audit = this.getDefaultAuditObj({ resource, region: this.region })

      audit.name = resource
      audit.comment = err.code

      if (err.code === 'NoSuchPublicAccessBlockConfiguration') {
        audit.state = 'FAIL'
        audit.comment = err.code
      }
      this.audits.push(audit)
    }
  }

  validate = (
    getPublicAccessBlock: GetPublicAccessBlockOutput,
    bucketName: string
  ) => {
    const config = getPublicAccessBlock.PublicAccessBlockConfiguration as {
      [key: string]: boolean
    }

    const audit = this.getDefaultAuditObj({
      resource: bucketName,
      region: this.region,
    })

    if (config[this.rule] === true) {
      audit.state = 'OK'
    } else if (config[this.rule] === false) {
      audit.state = 'FAIL'
      audit.comment = `${this.rule} explicitly disabled`
    } else {
      audit.comment = `${this.rule} unknown state`
    }
    this.audits.push(audit)
  }

  scan = async ({ resourceId }: { resourceId: string }) => {
    if (resourceId) {
      await this.audit({ resource: resourceId })
    } else {
      const options = this.getOptions()

      const promise = new this.AWS.S3(options).listBuckets().promise()
      const buckets = await this.pager<Bucket>(promise, 'Buckets')

      for (const bucket of buckets) {
        assert(bucket.Name, 'bucket does not have a name')
        await this.audit({ resource: bucket.Name })
      }
    }
  }
}
