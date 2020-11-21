import {
  AuditResultInterface,
  AWSScannerInterface,
} from '@lstatro/cloud-search'
import { GetCredentialReportResponse } from 'aws-sdk/clients/iam'
import assert from 'assert'
import { AWS } from '../../../../../lib/aws/AWS'
import { parse } from 'papaparse'

const rule = 'RootUserMfaEnabled'

export const command = `${rule} [args]`

export const desc = `The account root user should had MFA enabled 

  OK      - Root user has MFA enabled 
  WARNING - The credential report is older then 90 days
  UNKNOWN - Unable to determine if the root user has MFA enabled 
  FAIL    - Root user does not have MFA enabled

`

export class RootUserMfaEnabled extends AWS {
  service = 'iam'
  global = true

  constructor(public params: AWSScannerInterface) {
    super({ ...params, rule })
  }

  startReview = ({
    report,
    audit,
  }: {
    report?: GetCredentialReportResponse
    audit: AuditResultInterface
  }) => {
    try {
      assert(report, 'unable to find report')
      assert(report.GeneratedTime, 'report missing generation time')
      assert(report.Content, 'missing report data')

      const now = new Date()
      const max = this.addDays(now, 7)
      const generatedTime = new Date(report.GeneratedTime)
      assert(generatedTime.getTime() < max.getTime(), 'report too old to use')

      const json = parse(report.Content.toString())
      console.log(json)
    } catch (err) {
      //
    }
  }

  async audit() {
    const audit = this.getDefaultAuditObj({
      resource: 'root-user',
      region: this.region,
    })

    const options = this.getOptions()

    let report

    try {
      report = await new this.AWS.IAM(options).getCredentialReport().promise()
    } catch (err) {
      audit.comment = 'unable to get report'
      if (err.code === 'ReportNotPresent') {
        await new this.AWS.IAM(options).generateCredentialReport().promise()
        await this.sleep(5000)
        report = await new this.AWS.IAM(options).getCredentialReport().promise()
      }
    }

    this.audits.push(audit)
  }

  scan = async () => {
    /** nothing to scan, there is only a single root user */
    await this.audit()
  }
}

export const handler = async (args: AWSScannerInterface) => {
  const scanner = new RootUserMfaEnabled(args)

  await scanner.start()
  scanner.output()
  return scanner.audits
}
