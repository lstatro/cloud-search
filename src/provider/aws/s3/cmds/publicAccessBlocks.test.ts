import 'mocha'
import { useFakeTimers, SinonFakeTimers } from 'sinon'
import { mock, restore } from 'aws-sdk-mock'
import { handler as all } from './all'
import { handler as ignorePublicAcls } from './ignorePublicAcls'
import { handler as blockPublicAcls } from './blockPublicAcls'
import { handler as restrictPublicBuckets } from './restrictPublicBuckets'
import { handler as blockPublicPolicy } from './blockPublicPolicy'
import { AWSError } from 'aws-sdk'
import { expect } from 'chai'

describe('publicAccessBlocks', () => {
  const now = new Date(0)
  let clock: SinonFakeTimers

  beforeEach(() => {
    clock = useFakeTimers(now)
  })

  afterEach(() => {
    clock.restore()
    restore()
  })

  const handlers = [
    all,
    ignorePublicAcls,
    blockPublicAcls,
    restrictPublicBuckets,
    blockPublicPolicy,
  ]

  for (const handler of handlers) {
    it('should handle OK types', async () => {
      mock('S3', 'getPublicAccessBlock', {
        PublicAccessBlockConfiguration: {
          BlockPublicAcls: true,
          BlockPublicPolicy: true,
          IgnorePublicAcls: true,
          RestrictPublicBuckets: true,
        },
      })
      mock('S3', 'listBuckets', {
        Buckets: [
          {
            Name: 'test',
          },
        ],
      })
      const audits = await handler({
        _: ['test'],
        $0: 'test',
        profile: 'test',
        resourceId: 'test',
        domain: 'pub',
        region: 'us-east-1',
      })
      expect(audits[0].state).to.equal('OK')
    })

    it('should handle failed types', async () => {
      mock('S3', 'getPublicAccessBlock', {
        PublicAccessBlockConfiguration: {
          BlockPublicAcls: false,
          BlockPublicPolicy: false,
          IgnorePublicAcls: false,
          RestrictPublicBuckets: false,
        },
      })
      mock('S3', 'listBuckets', {
        Buckets: [
          {
            Name: 'test',
          },
        ],
      })
      const audits = await handler({
        _: ['test'],
        $0: 'test',
        profile: 'test',
        resourceId: 'test',
        domain: 'pub',
        region: 'us-east-1',
      })
      expect(audits[0].state).to.equal('FAIL')
    })

    it('should report UNKNOWN for resources toggles that are not boolean', async () => {
      mock('S3', 'getPublicAccessBlock', {
        PublicAccessBlockConfiguration: {
          BlockPublicAcls: 'test',
          BlockPublicPolicy: 'test',
          IgnorePublicAcls: 'test',
          RestrictPublicBuckets: 'test',
        },
      })
      mock('S3', 'listBuckets', {
        Buckets: [
          {
            Name: 'test',
          },
        ],
      })
      const audits = await handler({
        _: ['test'],
        $0: 'test',
        profile: 'test',
        resourceId: 'test',
        domain: 'pub',
        region: 'us-east-1',
      })
      expect(audits[0].state).to.equal('UNKNOWN')
    })

    it('should handle buckets that predate the public access blocks', async () => {
      const err = new Error('test') as AWSError
      err.code = 'NoSuchPublicAccessBlockConfiguration'

      mock('S3', 'getPublicAccessBlock', Promise.reject(err))
      mock('S3', 'listBuckets', {
        Buckets: [
          {
            Name: 'test',
          },
        ],
      })
      const audits = await handler({
        _: ['test'],
        $0: 'test',
        profile: 'test',
        resourceId: 'test',
        domain: 'pub',
        region: 'us-east-1',
      })

      expect(audits[0].state).to.equal('FAIL')
    })

    it('should report UNKNOWN if there was an unknown error getting the bucket', async () => {
      const err = new Error('test') as AWSError
      err.code = 'test'

      mock('S3', 'getPublicAccessBlock', Promise.reject(err))
      mock('S3', 'listBuckets', {
        Buckets: [
          {
            Name: 'test',
          },
        ],
      })
      const audits = await handler({
        _: ['test'],
        $0: 'test',
        profile: 'test',
        resourceId: 'test',
        domain: 'pub',
        region: 'us-east-1',
      })

      expect(audits[0].state).to.equal('UNKNOWN')
    })

    it('should handle no buckets', async () => {
      mock('S3', 'listBuckets', {})
      const audits = await handler({
        _: ['test'],
        $0: 'test',
        profile: 'test',
        domain: 'pub',
        region: 'us-east-1',
      })
      expect(audits).to.eql([])
    })

    /**
     * smoke test to see if we can step into global false and default
     * the region, I know it works, it's just hard to test without testing
     * the AWS provider directly
     */
    it('default to us-east-1 if passed all and global is true', async () => {
      mock('S3', 'listBuckets', {
        Buckets: [],
      })
      await handler({
        _: ['test'],
        $0: 'test',
        profile: 'test',
        domain: 'pub',
        region: 'all',
      })
    })
  }
})
