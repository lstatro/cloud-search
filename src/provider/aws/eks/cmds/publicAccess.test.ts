import { useFakeTimers, SinonFakeTimers, restore as sinonRestore } from 'sinon'
import { mock, restore } from 'aws-sdk-mock'
import { handler } from './publicAccess'
import { expect } from 'chai'

describe('#publicAccess', () => {
  const now = new Date(0)
  let clock: SinonFakeTimers

  beforeEach(() => {
    clock = useFakeTimers(now)
    mock('EC2', 'describeRegions', { Regions: [{ RegionName: 'us-east-1' }] })
  })

  afterEach(() => {
    clock.restore()
    restore()
    sinonRestore()
  })

  it('should report nothing if list clusters does not return a clusters attribute', async () => {
    mock('EKS', 'listClusters', {})

    const audits = await handler({
      region: 'us-east-1',
      profile: 'test',
      rule: 'PublicAccess',
    })
    expect(audits).to.eql([])
  })

  it('should report nothing if list clusters returns an empty array of clusters', async () => {
    mock('EKS', 'listClusters', { clusters: [] })

    const audits = await handler({
      region: 'us-east-1',
      profile: 'test',
      rule: 'PublicAccess',
    })
    expect(audits).to.eql([])
  })

  it('should report UNKNOWN if the cluster does not describe correctly', async () => {
    mock('EKS', 'listClusters', { clusters: ['test'] })
    mock('EKS', 'describeCluster', {})

    const audits = await handler({
      region: 'us-east-1',
      profile: 'test',
      rule: 'PublicAccess',
    })
    expect(audits).to.eql([
      {
        physicalId: 'test',
        profile: 'test',
        provider: 'aws',
        region: 'us-east-1',
        rule: 'PublicAccess',
        service: 'eks',
        state: 'UNKNOWN',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })

  it('should report UNKNOWN if the cluster does not have a resource vpc config', async () => {
    mock('EKS', 'listClusters', { clusters: ['test'] })
    mock('EKS', 'describeCluster', {
      cluster: {},
    })

    const audits = await handler({
      region: 'us-east-1',
      profile: 'test',
      resourceId: 'test',
      rule: 'PublicAccess',
    })
    expect(audits).to.eql([
      {
        physicalId: 'test',
        profile: 'test',
        provider: 'aws',
        region: 'us-east-1',
        rule: 'PublicAccess',
        service: 'eks',
        state: 'UNKNOWN',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })

  it('should report OK if the cluster is not public', async () => {
    mock('EKS', 'listClusters', { clusters: ['test'] })
    mock('EKS', 'describeCluster', {
      cluster: {
        resourcesVpcConfig: {
          endpointPublicAccess: false,
        },
      },
    })

    const audits = await handler({
      region: 'us-east-1',
      profile: 'test',
      rule: 'PublicAccess',
    })
    expect(audits).to.eql([
      {
        physicalId: 'test',
        profile: 'test',
        provider: 'aws',
        region: 'us-east-1',
        rule: 'PublicAccess',
        service: 'eks',
        state: 'OK',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })

  it('should report FAIL if the cluster is public', async () => {
    mock('EKS', 'listClusters', { clusters: ['test'] })
    mock('EKS', 'describeCluster', {
      cluster: {
        resourcesVpcConfig: {
          endpointPublicAccess: true,
        },
      },
    })

    const audits = await handler({
      region: 'us-east-1',
      profile: 'test',
      rule: 'PublicAccess',
    })
    expect(audits).to.eql([
      {
        physicalId: 'test',
        profile: 'test',
        provider: 'aws',
        region: 'us-east-1',
        rule: 'PublicAccess',
        service: 'eks',
        state: 'FAIL',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })
})
