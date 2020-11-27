import { mock, restore } from 'aws-sdk-mock'
import { useFakeTimers, SinonFakeTimers } from 'sinon'
import { handler } from './securityConfiguration'
import { expect } from 'chai'

describe('emr clusters should launch with a security configuration group', () => {
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

  it('should report nothing if list clusters does not return a clusters attribute', async () => {
    mock('EMR', 'listClusters', {})

    const audits = await handler({ region: 'all' })

    expect(audits).to.eql([])
  })

  it('should report nothing if list clusters returns an empty a clusters array', async () => {
    mock('EMR', 'listClusters', { Clusters: [] })

    const audits = await handler({ region: 'all' })

    expect(audits).to.eql([])
  })

  it('should report UNKNOWN if describe cluster does not return a cluster object', async () => {
    mock('EMR', 'listClusters', { Clusters: [{ Id: 'test' }] })
    mock('EMR', 'describeCluster', {})

    const audits = await handler({ region: 'all' })

    expect(audits).to.eql([
      {
        physicalId: 'test',
        profile: undefined,
        provider: 'aws',
        region: 'us-east-1',
        rule: 'SecurityConfiguration',
        service: 'emr',
        state: 'UNKNOWN',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })

  it('should report FAIL the cluster does not have a security configuration', async () => {
    mock('EMR', 'listClusters', { Clusters: [{ Id: 'test' }] })
    mock('EMR', 'describeCluster', { Cluster: {} })

    const audits = await handler({ region: 'all' })

    expect(audits).to.eql([
      {
        physicalId: 'test',
        profile: undefined,
        provider: 'aws',
        region: 'us-east-1',
        rule: 'SecurityConfiguration',
        service: 'emr',
        state: 'FAIL',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })

  it('should report OK if the cluster was launched with a security configuration', async () => {
    mock('EMR', 'listClusters', { Clusters: [{ Id: 'test' }] })
    mock('EMR', 'describeCluster', {
      Cluster: { SecurityConfiguration: 'test' },
    })

    const audits = await handler({
      region: 'us-east-1',
      resourceId: 'test',
      profile: 'test',
    })

    expect(audits).to.eql([
      {
        physicalId: 'test',
        profile: 'test',
        provider: 'aws',
        region: 'us-east-1',
        rule: 'SecurityConfiguration',
        service: 'emr',
        state: 'OK',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })
})
