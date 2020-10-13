import { GetPublicAccessBlockOutput } from 'aws-sdk/clients/s3'
import { AuditResultInterface, AWSScannerInterface } from 'cloud-search'
import assert from 'assert'
import AWS from '../../../../lib/aws/AWS'

interface PublicAccessBlocksInterface extends AWSScannerInterface {
  rule: string
}

export default class PublicAccessBlocks extends AWS {
  service = 's3'
  global = true

  constructor(public params: PublicAccessBlocksInterface) {
    super({
      profile: params.profile,
      resourceId: params.resourceId,
      region: params.region,
      rule: params.rule,
    })
  }

  async audit({ resourceId }: { resourceId: string }) {
    const s3 = new this.AWS.S3(this.options)
    try {
      const getPublicAccessBlock = await s3
        .getPublicAccessBlock({ Bucket: resourceId })
        .promise()
      assert(getPublicAccessBlock, 'unable to locate bucket')
      this.validate(getPublicAccessBlock, resourceId)
    } catch (err) {
      console.error(err.message)
      const auditObject: AuditResultInterface = {
        name: resourceId,
        comment: err.code,
        provider: 'aws',
        physicalId: resourceId,
        service: this.service,
        rule: this.rule,
        region: this.region,
        state: 'UNKNOWN',
        profile: this.profile,
        time: new Date().toISOString(),
      }
      if (err.code === 'NoSuchPublicAccessBlockConfiguration') {
        auditObject.state = 'FAIL'
        auditObject.comment = err.code
      }
      this.audits.push(auditObject)
    }
  }

  validate = (
    getPublicAccessBlock: GetPublicAccessBlockOutput,
    bucketName: string
  ) => {
    const config = getPublicAccessBlock.PublicAccessBlockConfiguration as {
      [key: string]: boolean
    }
    const auditObject: AuditResultInterface = {
      name: bucketName,
      provider: 'aws',
      physicalId: bucketName,
      service: this.service,
      rule: this.rule,
      region: this.region,
      state: 'UNKNOWN',
      profile: this.profile,
      time: new Date().toISOString(),
    }
    if (config[this.rule] === true) {
      auditObject.state = 'OK'
    } else if (config[this.rule] === false) {
      auditObject.state = 'FAIL'
      auditObject.comment = `${this.rule} explicitly disabled`
    } else {
      auditObject.comment = `${this.rule} unknown state`
    }
    this.audits.push(auditObject)
  }

  scan = async ({ resourceId }: { resourceId: string }) => {
    if (resourceId) {
      await this.audit({ resourceId })
    } else {
      const buckets = await this.listBuckets()
      for (const bucket of buckets) {
        assert(bucket.Name, 'bucket does not have a name')
        await this.audit({ resourceId: bucket.Name })
      }
    }
  }
}
