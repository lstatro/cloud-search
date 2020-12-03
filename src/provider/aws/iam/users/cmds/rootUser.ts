import {
  AuditResultInterface,
  AWSScannerInterface,
  UserReportJsonInterface,
} from '@lstatro/cloud-search'
import { GetCredentialReportResponse } from 'aws-sdk/clients/iam'
import assert from 'assert'
import { AWS } from '../../../../../lib/aws/AWS'
import { parse } from 'papaparse'

export type RootUserRuleType = 'MfaEnabled' | 'ApiKeys'

export interface RootUserMfaEnabledInterface extends AWSScannerInterface {
  sleep: number
  rule: RootUserRuleType
}

export class RootUser extends AWS {
  service = 'iam'
  global = true
  wait: number

  constructor(public params: RootUserMfaEnabledInterface) {
    super({ ...params })
    this.wait = params.sleep
  }

  mfaEnabled = (user: UserReportJsonInterface, audit: AuditResultInterface) => {
    if (user.mfa_active === 'true') {
      audit.state = 'OK'
    } else {
      audit.state = 'FAIL'
    }
  }

  apiKeys = (user: UserReportJsonInterface, audit: AuditResultInterface) => {
    const active = []
    if (user.access_key_1_active === 'true') {
      active.push('access_key_1_active')
    }

    if (user.access_key_2_active === 'true') {
      active.push('access_key_2_active')
    }

    if (active.length > 0) {
      audit.state = 'FAIL'
      audit.comment = active.join()
    } else {
      audit.state = 'OK'
    }
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
        const rules: {
          [key: string]: (
            user: UserReportJsonInterface,
            audit: AuditResultInterface
          ) => void
        } = {
          MfaEnabled: this.mfaEnabled,
          ApiKeys: this.apiKeys,
        }

        rules[this.rule](root, audit)
      } else {
        /** if we didn't find the root user we need to tell the user something is amiss */
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

        await this.sleep(+this.wait)
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
