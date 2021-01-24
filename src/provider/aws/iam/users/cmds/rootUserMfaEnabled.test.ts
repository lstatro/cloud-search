import {
  SinonFakeTimers,
  SinonStub,
  restore as sinonRestore,
  stub,
  useFakeTimers,
} from 'sinon'
import { mock, restore } from 'aws-sdk-mock'

import AWS from 'aws-sdk'
import { AWSError } from 'aws-sdk'
import { expect } from 'chai'
import { handler } from './rootUserMfaEnabled'
import papa from 'papaparse'

const csv_fail = `user,arn,user_creation_time,password_enabled,password_last_used,password_last_changed,password_next_rotation,mfa_active,access_key_1_active,access_key_1_last_rotated,access_key_1_last_used_date,access_key_1_last_used_region,access_key_1_last_used_service,access_key_2_active,access_key_2_last_rotated,access_key_2_last_used_date,access_key_2_last_used_region,access_key_2_last_used_service,cert_1_active,cert_1_last_rotated,cert_2_active,cert_2_last_rotated
<root_account>,arn:aws:iam::test:root,2018-03-07T21:35:12+00:00,not_supported,2020-10-15T01:16:31+00:00,not_supported,not_supported,false,false,N/A,N/A,N/A,N/A,false,N/A,N/A,N/A,N/A,false,N/A,false,N/A
customer1,arn:aws:iam::test:user/customer1,2019-12-28T20:00:51+00:00,false,N/A,N/A,N/A,false,true,2019-12-28T20:00:51+00:00,2020-11-21T20:38:00+00:00,us-east-1,iam,true,2020-09-25T03:06:58+00:00,N/A,N/A,N/A,false,N/A,false,N/A`

const csv_pass = `user,arn,user_creation_time,password_enabled,password_last_used,password_last_changed,password_next_rotation,mfa_active,access_key_1_active,access_key_1_last_rotated,access_key_1_last_used_date,access_key_1_last_used_region,access_key_1_last_used_service,access_key_2_active,access_key_2_last_rotated,access_key_2_last_used_date,access_key_2_last_used_region,access_key_2_last_used_service,cert_1_active,cert_1_last_rotated,cert_2_active,cert_2_last_rotated
<root_account>,arn:aws:iam::test:root,2018-03-07T21:35:12+00:00,not_supported,2020-10-15T01:16:31+00:00,not_supported,not_supported,true,false,N/A,N/A,N/A,N/A,false,N/A,N/A,N/A,N/A,false,N/A,false,N/A
customer1,arn:aws:iam::test:user/customer1,2019-12-28T20:00:51+00:00,false,N/A,N/A,N/A,false,true,2019-12-28T20:00:51+00:00,2020-11-21T20:38:00+00:00,us-east-1,iam,true,2020-09-25T03:06:58+00:00,N/A,N/A,N/A,false,N/A,false,N/A`

const csv_not_found = `user,arn,user_creation_time,password_enabled,password_last_used,password_last_changed,password_next_rotation,mfa_active,access_key_1_active,access_key_1_last_rotated,access_key_1_last_used_date,access_key_1_last_used_region,access_key_1_last_used_service,access_key_2_active,access_key_2_last_rotated,access_key_2_last_used_date,access_key_2_last_used_region,access_key_2_last_used_service,cert_1_active,cert_1_last_rotated,cert_2_active,cert_2_last_rotated
customer1,arn:aws:iam::test:user/customer1,2019-12-28T20:00:51+00:00,false,N/A,N/A,N/A,false,true,2019-12-28T20:00:51+00:00,2020-11-21T20:38:00+00:00,us-east-1,iam,true,2020-09-25T03:06:58+00:00,N/A,N/A,N/A,false,N/A,false,N/A`

describe('MfaEnabled', () => {
  const now = new Date(0)
  let clock: SinonFakeTimers

  let errStub: SinonStub

  beforeEach(() => {
    clock = useFakeTimers({ now, shouldAdvanceTime: true })
    errStub = stub(console, 'error')
    mock('EC2', 'describeRegions', { Regions: [{ RegionName: 'us-east-1' }] })
  })

  afterEach(() => {
    clock.restore()
    errStub.restore()
    sinonRestore()
    restore()
  })

  it('should UNKNOWN if an unexpected getReport call is returned', async () => {
    mock('IAM', 'getCredentialReport', undefined)

    const audits = await handler({
      region: 'all',
      sleep: 0,
      rule: 'MfaEnabled',
    })

    expect(audits).to.eql([
      {
        provider: 'aws',
        physicalId: 'root-user',
        service: 'iam',
        rule: 'MfaEnabled',
        region: 'global',
        state: 'UNKNOWN',
        profile: undefined,
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })

  it('should report UNKNOWN if missing report data', async () => {
    mock('IAM', 'getCredentialReport', {
      GeneratedTime: new Date(0).toISOString(),
    })

    const audits = await handler({
      region: 'all',
      sleep: 0,
      rule: 'MfaEnabled',
    })

    expect(errStub.args[0][0].message).to.eql('missing report data')
    expect(audits).to.eql([
      {
        provider: 'aws',
        physicalId: 'root-user',
        service: 'iam',
        rule: 'MfaEnabled',
        region: 'global',
        state: 'UNKNOWN',
        profile: undefined,
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })

  it('should report UNKNOWN if unable to parse csv', async () => {
    mock('IAM', 'getCredentialReport', {
      GeneratedTime: new Date(0).toISOString(),
      Content: 'test',
    })

    const err = 'test error'

    stub(papa, 'parse').throws(new Error(err))

    const audits = await handler({
      region: 'all',
      sleep: 0,
      rule: 'MfaEnabled',
    })

    expect(errStub.args[0][0].message).to.eql(err)
    expect(audits).to.eql([
      {
        provider: 'aws',
        physicalId: 'root-user',
        service: 'iam',
        rule: 'MfaEnabled',
        region: 'global',
        state: 'UNKNOWN',
        profile: undefined,
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })

  it('should report WARNING if the root user is not found', async () => {
    mock('IAM', 'getCredentialReport', {
      GeneratedTime: new Date(0).toISOString(),
      Content: csv_not_found,
    })

    const audits = await handler({
      region: 'all',
      sleep: 0,
      rule: 'MfaEnabled',
    })

    expect(audits).to.eql([
      {
        provider: 'aws',
        physicalId: 'root-user',
        service: 'iam',
        rule: 'MfaEnabled',
        region: 'global',
        state: 'WARNING',
        profile: undefined,
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })

  it('should report UNKNOWN if the get credential report errors for anything other then report not found', async () => {
    const err = new Error('test') as AWSError
    err.code = 'test'

    mock('IAM', 'getCredentialReport', Promise.reject(err))
    mock('IAM', 'generateCredentialReport', {})

    const audits = await handler({
      region: 'all',
      sleep: 0,
      rule: 'MfaEnabled',
    })

    expect(audits).to.eql([
      {
        provider: 'aws',
        physicalId: 'root-user',
        service: 'iam',
        rule: 'MfaEnabled',
        region: 'global',
        state: 'UNKNOWN',
        profile: undefined,
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })

  it('should attempt to get the generate the credential report if it is not found', async () => {
    const err = new Error('test') as AWSError
    err.code = 'ReportNotPresent'

    const getCredentialReportStub = stub()
    const generateCredentialReportStub = stub()

    getCredentialReportStub.onCall(0).throws(err)
    getCredentialReportStub.onCall(1).returns({
      GeneratedTime: new Date(0).toISOString(),
      Content: csv_pass,
    })

    stub(AWS, 'IAM').returns({
      getCredentialReport: () => {
        return {
          promise: getCredentialReportStub,
        }
      },
      generateCredentialReport: () => {
        return {
          promise: generateCredentialReportStub,
        }
      },
    })

    await handler({ region: 'all', sleep: 0, rule: 'MfaEnabled' })

    expect(getCredentialReportStub.callCount).to.eql(2)
    expect(generateCredentialReportStub.callCount).to.eql(1)
  }).timeout(10000)

  it('should report FAIL if MFA is disabled', async () => {
    mock('IAM', 'getCredentialReport', {
      GeneratedTime: new Date(0).toISOString(),
      Content: csv_fail,
    })

    const audits = await handler({
      region: 'all',
      sleep: 0,
      rule: 'MfaEnabled',
    })

    expect(audits).to.eql([
      {
        provider: 'aws',
        physicalId: 'root-user',
        service: 'iam',
        rule: 'MfaEnabled',
        region: 'global',
        state: 'FAIL',
        profile: undefined,
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })

  it('should report OK if MFA is enabled', async () => {
    mock('IAM', 'getCredentialReport', {
      GeneratedTime: new Date(0).toISOString(),
      Content: csv_pass,
    })

    const audits = await handler({
      region: 'all',
      sleep: 0,
      rule: 'MfaEnabled',
    })

    expect(audits).to.eql([
      {
        provider: 'aws',
        physicalId: 'root-user',
        service: 'iam',
        rule: 'MfaEnabled',
        region: 'global',
        state: 'OK',
        profile: undefined,
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })
})
