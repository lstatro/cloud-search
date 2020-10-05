import 'mocha'
import { mock, restore } from 'aws-sdk-mock'
import { handler, BucketEncryptedCliInterface } from './bucketEncryption'
import { expect } from 'chai'
describe('iam user key age', () => {
  beforeEach(() => {
    mock('EC2', 'describeRegions', { Regions: [{ RegionName: 'us-east-1' }] })
  })

  afterEach(() => {
    restore()
  })

  it('should report FAIL for buckets with no encryption', async () => {
    mock('S3', 'listBuckets', {
      Buckets: [
        {
          Name: 'test',
        },
      ],
    })
    mock('S3', 'getBucketEncryption', {
      ServerSideEncryptionConfiguration: {
        Rules: [],
      },
    })
    const audits = await handler({
      resourceId: 'test',
      domain: 'pub',
      region: 'test',
      keyType: 'aws',
    } as BucketEncryptedCliInterface)

    expect(audits[0].state).to.eql('FAIL')
  })
})
