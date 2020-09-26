import 'mocha'
import 'aws-sdk-mock'
import { handler as all } from './all'
import { handler as ignorePublicAcls } from './ignorePublicAcls'
import { handler as blockPublicAcls } from './blockPublicAcls'
import { handler as restrictPublicBuckets } from './restrictPublicBuckets'
import { handler as blockPublicPolicy } from './blockPublicPolicy'
import AWS from 'aws-sdk-mock'
import { AWSError } from 'aws-sdk'

describe('publicAccessBlocks', () => {
  const handlers = [
    all,
    ignorePublicAcls,
    blockPublicAcls,
    restrictPublicBuckets,
    blockPublicPolicy,
  ]

  for (const handler of handlers) {
    it('should handle passing types', async () => {
      AWS.mock('S3', 'getPublicAccessBlock', {
        PublicAccessBlockConfiguration: {
          BlockPublicAcls: true,
          BlockPublicPolicy: true,
          IgnorePublicAcls: true,
          RestrictPublicBuckets: true,
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
      AWS.restore()
    })
    it('should handle failed types', async () => {
      AWS.mock('S3', 'getPublicAccessBlock', {
        PublicAccessBlockConfiguration: {
          BlockPublicAcls: false,
          BlockPublicPolicy: false,
          IgnorePublicAcls: false,
          RestrictPublicBuckets: false,
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
      AWS.restore()
    })
    it('should handle unknown block types', async () => {
      AWS.mock('S3', 'getPublicAccessBlock', {
        PublicAccessBlockConfiguration: {
          BlockPublicAcls: 'test',
          BlockPublicPolicy: 'test',
          IgnorePublicAcls: 'test',
          RestrictPublicBuckets: 'test',
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
      AWS.restore()
    })
    it('should handle unknown types', async () => {
      const err = new Error('test') as AWSError
      AWS.mock('S3', 'getPublicAccessBlock', Promise.reject(err))
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
      AWS.restore()
    })
    it('should handle NoSuchPublicAccessBlockConfiguration', async () => {
      const err = new Error('test') as AWSError
      err.code = 'NoSuchPublicAccessBlockConfiguration'

      AWS.mock('S3', 'getPublicAccessBlock', Promise.reject(err))
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
      AWS.restore()
    })
    it('should handle no buckets', async () => {
      AWS.mock('S3', 'listBuckets', {})
      await handler({
        _: ['test'],
        $0: 'test',
        profile: 'test',
        resourceId: 'test',
        domain: 'pub',
        region: 'us-east-1',
      })
      AWS.restore()
    })
  }
})
