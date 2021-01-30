import { SinonFakeTimers, restore as sinonRestore, useFakeTimers } from 'sinon'
import { mock, restore } from 'aws-sdk-mock'

import { expect } from 'chai'
import { handler } from './secretsEncryption'

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

  it('should report nothing if list clusters does not return a clusters attribute', async () => {
    mock('EKS', 'listClusters', {})

    const audits = await handler({
      region: 'us-east-1',
      profile: 'test',
      keyType: 'aws',
      rule: 'SecretsEncryption',
    })
    expect(audits).to.eql([])
  })

  it('should report nothing if list clusters returns an empty array of clusters', async () => {
    mock('EKS', 'listClusters', { clusters: [] })

    const audits = await handler({
      region: 'us-east-1',
      profile: 'test',
      keyType: 'aws',
      rule: 'SecretsEncryption',
    })
    expect(audits).to.eql([])
  })

  it('should report UNKNOWN if the cluster fails to describe', async () => {
    mock('EKS', 'listClusters', { clusters: ['test'] })
    mock('EKS', 'describeCluster', {})

    const audits = await handler({
      region: 'us-east-1',
      profile: 'test',
      keyType: 'aws',
      rule: 'SecretsEncryption',
    })

    expect(audits).to.eql([
      {
        physicalId: 'test',
        profile: 'test',
        provider: 'aws',
        region: 'us-east-1',
        rule: 'SecretsEncryption',
        service: 'eks',
        state: 'UNKNOWN',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })

  it('should report FAIL if the cluster does not have an encryption config', async () => {
    mock('EKS', 'listClusters', { clusters: ['test'] })
    mock('EKS', 'describeCluster', {
      cluster: {},
    })

    const audits = await handler({
      region: 'us-east-1',
      profile: 'test',
      keyType: 'aws',
      rule: 'SecretsEncryption',
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

  it('should report FAIL if the cluster encryption config does not have a resources array', async () => {
    mock('EKS', 'listClusters', { clusters: ['test'] })
    mock('EKS', 'describeCluster', {
      cluster: {
        encryptionConfig: [{}],
      },
    })

    const audits = await handler({
      region: 'us-east-1',
      profile: 'test',
      keyType: 'aws',
      rule: 'SecretsEncryption',
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

  it('should report FAIL if the clusters encryption resources config does not include secrets', async () => {
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
      resource: 'test',
      keyType: 'aws',
      rule: 'SecretsEncryption',
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

  it('should report FAIL the clusters encryption does not have a provider', async () => {
    mock('EKS', 'listClusters', { clusters: ['test'] })
    mock('EKS', 'describeCluster', {
      cluster: {
        encryptionConfig: [
          {
            resources: ['secrets'],
          },
        ],
      },
    })

    const audits = await handler({
      region: 'us-east-1',
      profile: 'test',
      keyType: 'aws',
      rule: 'SecretsEncryption',
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

  it('should report FAIL the clusters encryption provider does not have a a key arn', async () => {
    mock('EKS', 'listClusters', { clusters: ['test'] })
    mock('EKS', 'describeCluster', {
      cluster: {
        encryptionConfig: [
          {
            resources: ['secrets'],
            provider: {},
          },
        ],
      },
    })

    const audits = await handler({
      region: 'us-east-1',
      profile: 'test',
      keyType: 'aws',
      rule: 'SecretsEncryption',
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

  it('should report OK the clusters encryption provider provides an AWS managed key arn when looking for any key', async () => {
    mock('KMS', 'describeKey', {
      KeyMetadata: { Arn: 'test', KeyManager: 'AWS' },
    })
    mock('EKS', 'listClusters', { clusters: ['test'] })
    mock('EKS', 'describeCluster', {
      cluster: {
        encryptionConfig: [
          {
            resources: ['secrets'],
            provider: { keyArn: 'test' },
          },
        ],
      },
    })

    const audits = await handler({
      region: 'us-east-1',
      profile: 'test',
      keyType: 'aws',
      rule: 'SecretsEncryption',
    })

    expect(audits).to.eql([
      {
        physicalId: 'test',
        profile: 'test',
        provider: 'aws',
        region: 'us-east-1',
        rule: 'SecretsEncryption',
        service: 'eks',
        state: 'OK',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })

  it('should report WARNING if the clusters encryption provider provides a AWS managed key arn', async () => {
    mock('KMS', 'describeKey', {
      KeyMetadata: { Arn: 'test', KeyManager: 'AWS' },
    })
    mock('EKS', 'listClusters', { clusters: ['test'] })
    mock('EKS', 'describeCluster', {
      cluster: {
        encryptionConfig: [
          {
            resources: ['secrets'],
            provider: { keyArn: 'test' },
          },
        ],
      },
    })

    const audits = await handler({
      region: 'us-east-1',
      profile: 'test',
      keyType: 'cmk',
      rule: 'SecretsEncryption',
    })

    expect(audits).to.eql([
      {
        physicalId: 'test',
        profile: 'test',
        provider: 'aws',
        region: 'us-east-1',
        rule: 'SecretsEncryption',
        service: 'eks',
        state: 'WARNING',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })

  it('should report OK if the clusters encryption provider provides a customer managed key arn', async () => {
    mock('KMS', 'describeKey', {
      KeyMetadata: { Arn: 'test', KeyManager: 'CUSTOMER' },
    })
    mock('EKS', 'listClusters', { clusters: ['test'] })
    mock('EKS', 'describeCluster', {
      cluster: {
        encryptionConfig: [
          {
            resources: ['secrets'],
            provider: { keyArn: 'test' },
          },
        ],
      },
    })

    const audits = await handler({
      region: 'us-east-1',
      profile: 'test',
      keyType: 'cmk',
      rule: 'SecretsEncryption',
    })

    expect(audits).to.eql([
      {
        physicalId: 'test',
        profile: 'test',
        provider: 'aws',
        region: 'us-east-1',
        rule: 'SecretsEncryption',
        service: 'eks',
        state: 'OK',
        time: '1970-01-01T00:00:00.000Z',
      },
    ])
  })
})
