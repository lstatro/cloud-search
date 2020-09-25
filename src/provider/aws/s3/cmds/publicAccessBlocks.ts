import { S3 } from 'aws-sdk'
import { GetPublicAccessBlockOutput } from 'aws-sdk/clients/s3'
import { AuditResultInterface, AWSScannerInterface } from 'cloud-scan'
import assert from 'assert'
import AWS from '../../../../lib/aws/AWS'

interface PublicAccessBlocksInterface extends AWSScannerInterface {
  rule: string
}

export default class PublicAccessBlocks extends AWS {
  audits: AuditResultInterface[] = []
  service = 's3'
  global = true

  constructor(public params: PublicAccessBlocksInterface) {
    super({
      profile: params.profile,
      resourceId: params.resourceId,
      domain: params.domain,
      region: params.region,
      rule: params.rule,
    })
  }

  async audit(bucketName: string, region: string) {
    const s3 = new S3(this.options)
    try {
      const getPublicAccessBlock = await s3
        .getPublicAccessBlock({ Bucket: bucketName })
        .promise()
      assert(getPublicAccessBlock, 'unable to locate bucket')
      this.validate(getPublicAccessBlock, bucketName)
    } catch (err) {
      const auditObject: AuditResultInterface = {
        name: bucketName,
        comment: err.code,
        provider: 'aws',
        physicalId: bucketName,
        service: this.service,
        rule: this.rule,
        region: region,
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
    }
    this.audits.push(auditObject)
  }

  scan = async () => {
    const s3 = new S3(this.options)

    const listBuckets = await s3.listBuckets().promise()
    if (listBuckets.Buckets)
      for (const bucket of listBuckets.Buckets) {
        assert(bucket.Name, 'bucket does nto have a name')
        await this.audit(bucket.Name, this.region)
      }
  }
}
