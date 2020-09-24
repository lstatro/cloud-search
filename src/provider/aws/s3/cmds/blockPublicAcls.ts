import { S3 } from 'aws-sdk'
import { GetPublicAccessBlockOutput } from 'aws-sdk/clients/s3'
import {
  AuditResultInterface,
  AWSScannerInterface,
  AWSScannerCliArgsInterface,
} from 'cloud-scan'
import assert from 'assert'
import toTerminal from '../../../../lib/toTerminal'
import AWS from '../../../../lib/aws/AWS'

const rule = 'blockPublicAcls'

export const command = `${rule} [args]`
export const desc = 'Verifies the block public ACLs toggle on s3 buckets'

export default class BlockPublicAcls extends AWS {
  audits: AuditResultInterface[] = []
  service = 's3'
  global = true

  constructor(public params: AWSScannerInterface) {
    super({
      profile: params.profile,
      resourceId: params.resourceId,
      domain: params.domain,
      region: params.region,
      rule,
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
        rule,
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
    const config = getPublicAccessBlock.PublicAccessBlockConfiguration
    const auditObject: AuditResultInterface = {
      name: bucketName,
      provider: 'aws',
      physicalId: bucketName,
      service: this.service,
      rule,
      region: this.region,
      state: 'UNKNOWN',
      profile: this.profile,
      time: new Date().toISOString(),
    }
    if (config?.BlockPublicAcls === true) {
      auditObject.state = 'OK'
    } else if (config?.BlockPublicAcls === false) {
      auditObject.state = 'FAIL'
      auditObject.comment = 'BlockPublicAcls explicitly disabled'
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

export const handler = async (args: AWSScannerCliArgsInterface) => {
  const scanner = await new BlockPublicAcls({
    region: args.region,
    profile: args.profile,
    resourceId: args.resourceId,
    domain: args.domain,
  })
  await scanner.start()
  toTerminal(scanner.audits)
}
