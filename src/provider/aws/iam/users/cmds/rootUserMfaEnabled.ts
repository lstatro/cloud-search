import {
  AuditResultInterface,
  AWSScannerInterface,
  UserReportJsonInterface,
} from '@lstatro/cloud-search'
import { GetCredentialReportResponse } from 'aws-sdk/clients/iam'
import assert from 'assert'
import { AWS, sleepArg } from '../../../../../lib/aws/AWS'
import { parse } from 'papaparse'

const rule = 'RootUserMfaEnabled'

export const builder = {
  ...sleepArg,
}

export const command = `${rule} [args]`

export const desc = `A root user should had MFA enabled 

  OK      - Root user has MFA enabled
  WARNING - Unable to find the root user in the credentials report
  UNKNOWN - Unable to determine if the root user has MFA enabled 
  FAIL    - Root user does not have MFA enabled

  note: This service works by parsing the IAM credentials report.  If the report
        is not found the service will request a new report and wait a few
        seconds and try again.

`

export interface RootUserMfaEnabledInterface extends AWSScannerInterface {
  wait: number
}

export class RootUserMfaEnabled extends AWS {
  service = 'iam'
  global = true
  wait: number

  constructor(public params: RootUserMfaEnabledInterface) {
    super({ ...params, rule })
    this.wait = params.wait
  }

  startReview = ({
    report,
    audit,
  }: {
    report: GetCredentialReportResponse
    audit: AuditResultInterface
  }) => {
    try {
      /** sanity check report */
      assert(report.Content, 'missing report data')

      const data = parse(report.Content.toString(), { header: true })
        .data as UserReportJsonInterface[]

      const root = data.find(({ user }) => user === '<root_account>')

      if (root) {
        if (root.mfa_active === 'true') {
          audit.state = 'OK'
        } else {
          audit.state = 'FAIL'
        }
      } else {
        audit.state = 'WARNING'
      }
    } catch (err) {
      console.error(err)
      /** do nothing, leave it as unknown */
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
      console.error(err)
      if (err.code === 'ReportNotPresent') {
        await new this.AWS.IAM(options).generateCredentialReport().promise()

        await this.sleep(this.wait)
        report = await new this.AWS.IAM(options).getCredentialReport().promise()
      }
    }

    if (report) {
      this.startReview({ report, audit })
    }

    this.audits.push(audit)
  }

  scan = async () => {
    /** nothing to scan, there is only a single root user */
    await this.audit()
  }
}

export const handler = async (args: RootUserMfaEnabledInterface) => {
  const scanner = new RootUserMfaEnabled(args)

  await scanner.start()
  scanner.output()
  return scanner.audits
}
