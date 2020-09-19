import { S3 } from 'aws-sdk'
import { GetPublicAccessBlockOutput } from 'aws-sdk/clients/s3'
import { AuditResultInterface } from 'cloud-scan'
import { Arguments } from 'yargs'
import ora, { Ora } from 'ora'
import assert from 'assert'
import getOptions from '../../../../lib/aws/options'
import toTerminal from '../../../../lib/toTerminal'

const rule = 'blockPublicAcls'

export const command = `${rule} [args]`
export const desc = 'report on the block public ACLs toggle'

export class Scanner {
  options: { [key: string]: string | undefined }
  audits: AuditResultInterface[] = []
  service = 's3'
  spinner: Ora

  constructor(
    public region: string,
    public profile: string,
    public resourceId: string
  ) {
    this.region = 'n/a'
    this.options = getOptions(profile)
    this.spinner = ora({
      prefixText: rule,
    })
  }

  start = async () => {
    try {
      this.spinner.start()
      if (this.resourceId) {
        await this.audit(this.resourceId)
      } else {
        await this.scan()
      }
      this.spinner.succeed()
    } catch (err) {
      this.spinner.fail(err.code)
    }
  }

  audit = async (bucketName?: string) => {
    const s3 = new S3(this.options)
    try {
      assert(bucketName, 'bucket has no name')
      this.spinner.text = bucketName
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
    this.spinner.text = ''
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
