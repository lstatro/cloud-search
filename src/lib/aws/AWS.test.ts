import 'mocha'
import { expect } from 'chai'
import { mock, restore } from 'aws-sdk-mock'
import AWS from './AWS'
import _AWS from 'aws-sdk'

class AwsTestClass extends AWS {
  service = 'test'
  constructor() {
    super({
      profile: 'test',
      resourceId: 'test',
      domain: 'pub',
      region: 'us-east-1',
      rule: 'test',
    })
  }
  audit = async () => undefined
  scan = async () => undefined
}

describe('aws base class', () => {
  beforeEach(() => {
    mock('EC2', 'describeRegions', { Regions: [{ RegionName: 'us-east-1' }] })
  })

  afterEach(() => {
    restore()
  })

  it('should should return a promise result', async () => {
    mock('SNS', 'listTopics', 'test')
    const aws = new AwsTestClass()
    const client = new _AWS.SNS()
    const response = await aws.call(client.listTopics().promise())
    expect(response).to.eql('test')
  })

  it('should should throw for errors that are not retryable', async () => {
    const err = new Error('test') as AWS.AWSError
    mock('SNS', 'listTopics', Promise.reject(err))
    const aws = new AwsTestClass()
    const client = new _AWS.SNS()
    let response
    try {
      response = await aws.call(client.listTopics().promise())
    } catch (err) {
      response = err
    }
    expect(response).to.be.instanceOf(Error)
  })

  it('should return a number', () => {
    const aws = new AwsTestClass()
    expect(typeof aws.getBackOff(1)).to.eql('number')
  })
})
