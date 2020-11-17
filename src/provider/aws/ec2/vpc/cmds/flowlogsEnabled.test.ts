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

  it('should return OK when passed in a ResourceId that has FlowLogs enabled ', async () => {
    mock('EC2', 'describeFlowLogs', {
      FlowLogs: [{ ResourceId: 'test' }],
    })
    let audits
    audits = await handler({
      region: 'test',
      profile: 'test',
      resourceId: 'test',
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
  it('should return FAIL when passed a ResourceId with no FlowLogs', async () => {
    mock('EC2', 'describeFlowLogs', {
      FlowLogs: [],
    })
    let audits
    audits = await handler({
      region: 'test',
      profile: 'test',
      resourceId: 'test',
    })
    expect(audits).to.eql([
      {
        physicalId: 'test',
        profile: 'test',
        provider: 'aws',
        region: 'test',
        rule: 'FlowlogsEnabled',
        service: 'ec2',
        state: 'FAIL',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })
  it('should return OK after listing VPCs, then checking if flowlogs are enabled', async () => {
    mock('EC2', 'describeVpcs', {
      Vpcs: [{ VpcId: 'test' }],
    })
    mock('EC2', 'describeFlowLogs', {
      FlowLogs: [
        {
          ResourceId: 'test',
        },
      ],
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
  it('should return FAIL after listing VPCs, then checking if flowlogs are enabled', async () => {
    mock('EC2', 'describeVpcs', {
      Vpcs: [
        {
          VpcId: 'test',
        },
      ],
    })
    mock('EC2', 'describeFlowLogs', {
      FlowLogs: [],
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
        state: 'FAIL',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })
})
