import { useFakeTimers, SinonFakeTimers, restore as sinonRestore } from 'sinon'
import { mock, restore } from 'aws-sdk-mock'
import { handler } from './secretsEncryption'
import { expect } from 'chai'

describe.only('eks secrets encryption', () => {
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
      keyType: 'aws',
    })
    expect(audits).to.eql([])
  })

  it('should report nothing if list clusters returns an empty array of clusters', async () => {
    mock('EKS', 'listClusters', { clusters: [] })

    const audits = await handler({
      region: 'us-east-1',
      profile: 'test',
      keyType: 'aws',
    })
    expect(audits).to.eql([])
  })

  it('should report FAIL if the cluster does not encrypt secrets', async () => {
    mock('EKS', 'listClusters', { clusters: ['test'] })
    mock('EKS', 'describeCluster', {
      cluster: {
        encryptionConfig: [
          {
            resources: ['test'],
          },
        ],
      },
    })

    const audits = await handler({
      region: 'us-east-1',
      profile: 'test',
      keyType: 'aws',
    })

    expect(audits).to.eql([
      {
        physicalId: 'test',
        profile: 'test',
        provider: 'aws',
        region: 'us-east-1',
        rule: 'SecretsEncryption',
        service: 'eks',
        state: 'FAIL',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })
})
