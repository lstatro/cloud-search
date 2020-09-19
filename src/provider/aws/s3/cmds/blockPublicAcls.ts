import { S3 } from 'aws-sdk'
import { GetPublicAccessBlockOutput } from 'aws-sdk/clients/s3'
import { AuditResultInterface } from 'cloud-scan'
import assert from 'assert'
import { Arguments } from 'yargs'
import getOptions from '../../../../lib/aws/options'
import buildAuditResult from '../../../../lib/buildAuditResult'
import toTerminal from '../../../../lib/toTerminal'

const rule = 'blockPublicAcls'

export const command = `${rule} [args]`
export const desc = 'report on s3 buckets block public ACLs toggle'

export class Scanner {
  options: { [key: string]: string | undefined }
  audits: AuditResultInterface[] = []
  service = 's3'

  constructor(
    public region: string,
    public profile: string,
    public resourceId: string
  ) {
    this.region = 'n/a'
    this.options = getOptions(profile)
  }

  start = async () => {
    if (this.resourceId) {
      // TODO
    } else {
      await this.scan()
    }
  }

  audit = async (bucketName?: string) => {
    const s3 = new S3(this.options)
    try {
      assert(bucketName, 'bucket has no name')
      const getPublicAccessBlock = await s3
        .getPublicAccessBlock({ Bucket: bucketName })
        .promise()
      assert(getPublicAccessBlock, 'unable to locate bucket')
      this.validate(getPublicAccessBlock, bucketName)
    } catch (err) {
      err._audit = {
        bucketName,
      }
      const auditObject = buildAuditResult({
        name: bucketName,
        provider: 'aws',
        physicalId: bucketName || 'missing bucket name',
        service: this.service,
        rule,
        region: this.region,
        state: 'UNKNOWN',
        profile: this.profile,
      })
      if (err.code === 'NoSuchPublicAccessBlockConfiguration') {
        auditObject.state = 'FAIL'
      }
      this.audits.push(auditObject)
    }
  }

  validate = (
    getPublicAccessBlock: GetPublicAccessBlockOutput,
    bucketName: string
  ) => {
    const config = getPublicAccessBlock.PublicAccessBlockConfiguration
    const auditObject = buildAuditResult({
      name: bucketName,
      provider: 'aws',
      physicalId: bucketName,
      service: this.service,
      rule,
      region: this.region,
      state: 'UNKNOWN',
      profile: this.profile,
    })
    if (config?.BlockPublicAcls === true) {
      auditObject.state = 'OK'
    } else if (config?.BlockPublicAcls === false) {
      auditObject.state = 'FAIL'
    }
    this.audits.push(auditObject)
  }

  scan = async () => {
    const s3 = new S3(this.options)

    const listBuckets = await s3.listBuckets().promise()
    if (listBuckets.Buckets)
      for (const bucket of listBuckets.Buckets) {
        await this.audit(bucket.Name)
      }
  }
}

export const handler = async (args: Arguments) => {
  const { region, profile, resourceId } = args
  const scanner = await new Scanner(
    region as string,
    profile as string,
    resourceId as string
  )
  await scanner.start()
  toTerminal(scanner.audits)
}
