import 'mocha'
import { mock, restore } from 'aws-sdk-mock'
import { handler, MaxKeyAgeCliInterface } from './passwordAge'
import { expect } from 'chai'
import { AWSError } from 'aws-sdk'
describe('passwordAge', () => {
  beforeEach(() => {
    mock('EC2', 'describeRegions', { Regions: [{ RegionName: 'us-east-1' }] })
  })

  afterEach(() => {
    restore()
  })

  it('should report FAIL for keys older then 90 days', async () => {
    mock('IAM', 'listUsers', {
      Users: [
        {
          UserName: 'test',
        },
      ],
    })
    mock('IAM', 'getLoginProfile', {
      LoginProfile: {
        CreateDate: new Date(0),
      },
    })

    const audits = await handler({
      domain: 'pub',
      region: 'all',
      maxAge: 90,
    } as MaxKeyAgeCliInterface)

    expect(audits[0].state).to.eql('FAIL')
  })

  it('should report OK for keys younger then 90 days', async () => {
    mock('IAM', 'listUsers', {
      Users: [
        {
          UserName: 'test',
        },
      ],
    })
    mock('IAM', 'getLoginProfile', {
      LoginProfile: {
        CreateDate: new Date(),
      },
    })

    const audits = await handler({
      domain: 'pub',
      region: 'all',
      maxAge: 90,
    } as MaxKeyAgeCliInterface)

    expect(audits[0].state).to.eql('OK')
  })

  it('should report OK for users without passwords', async () => {
    mock('IAM', 'listUsers', {
      Users: [
        {
          UserName: 'test',
        },
      ],
    })
    mock('IAM', 'getLoginProfile', {})

    const audits = await handler({
      domain: 'pub',
      region: 'all',
      maxAge: 90,
    } as MaxKeyAgeCliInterface)

    expect(audits[0].state).to.eql('OK')
  })

  it('should report OK for expected users without password errors', async () => {
    mock('IAM', 'listUsers', {
      Users: [
        {
          UserName: 'test',
        },
      ],
    })
    const err = new Error('test') as AWSError
    err.code = 'NoSuchEntity'
    mock('IAM', 'getLoginProfile', Promise.reject(err))

    const audits = await handler({
      domain: 'pub',
      region: 'all',
      maxAge: 90,
    } as MaxKeyAgeCliInterface)

    expect(audits[0].state).to.eql('OK')
  })
})
