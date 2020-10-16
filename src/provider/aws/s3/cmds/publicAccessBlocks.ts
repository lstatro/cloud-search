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
      verbosity: params.verbosity,
    })
  }

  async audit({ resource }: { resource: string }) {
    const s3 = new this.AWS.S3(this.options)
    try {
      const getPublicAccessBlock = await s3
        .getPublicAccessBlock({ Bucket: resource })
        .promise()
      assert(getPublicAccessBlock, 'unable to locate bucket')
      this.validate(getPublicAccessBlock, resource)
    } catch (err) {
      const auditObject: AuditResultInterface = {
        name: resource,
        comment: err.code,
        provider: 'aws',
        physicalId: resource,
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

  scan = async ({ resource }: { resource: string }) => {
    if (resource) {
      await this.audit({ resource })
    } else {
      const buckets = await this.listBuckets()
      for (const bucket of buckets) {
        assert(bucket.Name, 'bucket does not have a name')
        await this.audit({ resource: bucket.Name })
      }
    }
  }
}
