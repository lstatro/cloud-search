import 'mocha'
import { useFakeTimers, SinonFakeTimers } from 'sinon'
import { mock, restore } from 'aws-sdk-mock'
import { handler } from './flowlogsEnabled'
import { expect } from 'chai'

describe('vpc flowlogs enabled', () => {
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

  it('should return empty audits if no vpc instances are found ', async () => {
    mock('EC2', 'describeFlowLogs', [])
    let audits
    audits = await handler({
      region: 'test',
      profile: 'test',
    })
    expect(audits).to.eql([])
  })

  it('should return OK audit flowlog is found', async () => {
    mock('EC2', 'describeFlowLogs', {
      FlowLogs: [{ ResourceId: 'test' }],
    })
    let audits
    audits = await handler({
      region: 'test',
      profile: 'test',
    })
    expect(audits).to.eql([
      {
        physicalId: 'test',
        profile: 'test',
        provider: 'aws',
        region: 'test',
        rule: 'FlowlogsEnabled',
        service: 'ec2',
        state: 'OK',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })
  it('should return OK if flowlog is found and active', async () => {
    mock('EC2', 'describeFlowLogs', {
      FlowLogs: [{ FlowLogStatus: 'ACTIVE', ResourceId: 'test' }],
    })
    let audits
    audits = await handler({
      region: 'test',
      profile: 'test',
    })
    expect(audits).to.eql([
      {
        physicalId: 'test',
        profile: 'test',
        provider: 'aws',
        region: 'test',
        rule: 'FlowlogsEnabled',
        service: 'ec2',
        state: 'OK',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })
  it('should return FAIL if flowlog is found and not in ACTIVE state', async () => {
    mock('EC2', 'describeFlowLogs', {
      FlowLogs: [{ FlowLogStatus: 'ACTIVE', ResourceId: 'test' }],
    })
    let audits
    audits = await handler({
      region: 'test',
      profile: 'test',
    })
    expect(audits).to.eql([
      {
        physicalId: 'test',
        profile: 'test',
        provider: 'aws',
        region: 'test',
        rule: 'FlowlogsEnabled',
        service: 'ec2',
        state: 'OK',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })
})
