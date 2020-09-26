import 'mocha'
import 'aws-sdk-mock'
import { handler } from './blockPublicAcls'
import AWS from 'aws-sdk-mock'

describe('blockPublicAcls', () => {
  it('should attempt to invoke a test', async () => {
    AWS.mock('S3', 'getPublicAccessBlock', {
      PublicAccessBlockConfiguration: {
        BlockPublicAcls: false,
      },
    })
    AWS.mock('S3', 'listBuckets', {
      Buckets: [
        {
          Name: 'test',
        },
      ],
    })
    await handler({
      _: ['test'],
      $0: 'test',
      profile: 'test',
      resourceId: 'test',
      domain: 'pub',
      region: 'us-east-1',
    })
  })
})
