import { useFakeTimers, SinonFakeTimers, restore as sinonRestore } from 'sinon'
import { mock, restore } from 'aws-sdk-mock'
import { handler } from './apiLogging'
import { expect } from 'chai'

describe('eks secrets encryption', () => {
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

  it('should report OK if the cluster has api logging enabled', async () => {
    mock('EKS', 'listClusters', { clusters: ['test'] })
    mock('EKS', 'describeCluster', {
      cluster: {
        logging: {
          clusterLogging: [
            {
              types: ['api'],
              enabled: true,
            },
          ],
        },
      },
    })

    const audits = await handler({
      region: 'us-east-1',
      profile: 'test',
      rule: 'ApiLogging',
    })

    expect(audits).to.eql([
      {
        physicalId: 'test',
        profile: 'test',
        provider: 'aws',
        region: 'us-east-1',
        rule: 'ApiLogging',
        service: 'eks',
        state: 'OK',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })

  it('should report FAIL if the cluster does not have api logging enabled', async () => {
    mock('EKS', 'listClusters', { clusters: ['test'] })
    mock('EKS', 'describeCluster', {
      cluster: {
        logging: {
          clusterLogging: [
            {
              types: ['api'],
              enabled: false,
            },
          ],
        },
      },
    })

    const audits = await handler({
      region: 'us-east-1',
      profile: 'test',
      rule: 'ApiLogging',
    })

    expect(audits).to.eql([
      {
        physicalId: 'test',
        profile: 'test',
        provider: 'aws',
        region: 'us-east-1',
        rule: 'ApiLogging',
        service: 'eks',
        state: 'FAIL',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })
})
