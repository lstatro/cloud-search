import { useFakeTimers, SinonFakeTimers, restore as sinonRestore } from 'sinon'
import { mock, restore } from 'aws-sdk-mock'
import { handler } from './authenticatorLogging'
import { expect } from 'chai'

describe('#AuthenticatorLogging', () => {
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

  it('should report OK if the cluster has audit logging enabled', async () => {
    mock('EKS', 'listClusters', { clusters: ['test'] })
    mock('EKS', 'describeCluster', {
      cluster: {
        logging: {
          clusterLogging: [
            {
              types: ['authenticator'],
              enabled: true,
            },
          ],
        },
      },
    })

    const audits = await handler({
      region: 'us-east-1',
      profile: 'test',
      rule: 'AuthenticatorLogging',
    })

    expect(audits).to.eql([
      {
        physicalId: 'test',
        profile: 'test',
        provider: 'aws',
        region: 'us-east-1',
        rule: 'AuthenticatorLogging',
        service: 'eks',
        state: 'OK',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })

  it('should report FAIL if the cluster does not have audit logging enabled', async () => {
    mock('EKS', 'listClusters', { clusters: ['test'] })
    mock('EKS', 'describeCluster', {
      cluster: {
        logging: {
          clusterLogging: [
            {
              types: ['authenticator'],
              enabled: false,
            },
          ],
        },
      },
    })

    const audits = await handler({
      region: 'us-east-1',
      profile: 'test',
      rule: 'AuthenticatorLogging',
    })

    expect(audits).to.eql([
      {
        physicalId: 'test',
        profile: 'test',
        provider: 'aws',
        region: 'us-east-1',
        rule: 'AuthenticatorLogging',
        service: 'eks',
        state: 'FAIL',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })
})
