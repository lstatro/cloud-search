import { SinonFakeTimers, useFakeTimers } from 'sinon'
import { mock, restore } from 'aws-sdk-mock'

import { expect } from 'chai'
import { handler } from './encryptionEnabled'

/** test2 */

describe('cloudwatch log groups should be encrypted with a cmk at rest', () => {
  const now = new Date(0)
  let clock: SinonFakeTimers

  beforeEach(() => {
    clock = useFakeTimers(now)
    mock('EC2', 'describeRegions', { Regions: [{ RegionName: 'us-east-1' }] })
  })

  afterEach(() => {
    clock.restore()
    restore()
  })

  it('should report nothing if describe logs does not return a logGroups attribute', async () => {
    mock('CloudWatchLogs', 'describeLogGroups', {})

    const audits = await handler({ region: 'all' })

    expect(audits).to.eql([])
  })

  it('should report nothing if describe logs returns an empty array of logs', async () => {
    mock('CloudWatchLogs', 'describeLogGroups', { logGroups: [] })

    const audits = await handler({ region: 'us-east-1', resource: 'test' })

    expect(audits).to.eql([])
  })

  it('should report FAIL if the log group is not encrypted', async () => {
    mock('CloudWatchLogs', 'describeLogGroups', {
      logGroups: [
        {
          logGroupName: 'test',
        },
      ],
    })

    const audits = await handler({ region: 'us-east-1', resource: 'test' })

    expect(audits).to.eql([
      {
        physicalId: 'test',
        profile: undefined,
        provider: 'aws',
        region: 'us-east-1',
        rule: 'EncryptionEnabled',
        service: 'cloudwatch',
        state: 'FAIL',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })

  it('should report OK if the log group is encrypted', async () => {
    mock('CloudWatchLogs', 'describeLogGroups', {
      logGroups: [
        {
          logGroupName: 'test',
          kmsKeyId: 'test',
        },
      ],
    })

    mock('KMS', 'describeKey', { KeyMetadata: { KeyManager: 'CUSTOMER' } })

    const audits = await handler({ region: 'us-east-1', resource: 'test' })

    expect(audits).to.eql([
      {
        physicalId: 'test',
        profile: undefined,
        provider: 'aws',
        region: 'us-east-1',
        rule: 'EncryptionEnabled',
        service: 'cloudwatch',
        state: 'OK',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })
})
