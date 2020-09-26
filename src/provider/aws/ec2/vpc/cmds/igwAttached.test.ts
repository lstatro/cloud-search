import 'mocha'
import { mock, restore } from 'aws-sdk-mock'
import { handler } from './igwAttached'
import { AWSScannerCliArgsInterface } from 'cloud-search'

/** none of these tests should throw */

describe('igw vpc attachment', () => {
  beforeEach(() => {
    mock('EC2', 'describeRegions', { Regions: [{ RegionName: 'us-east-1' }] })
  })

  afterEach(() => {
    restore()
  })

  it('should report FAIL', async () => {
    mock('EC2', 'describeInternetGateways', {
      InternetGateways: [
        {
          Attachments: [
            {
              State: 'available',
            },
          ],
        },
      ],
    })
    await handler({
      region: 'us-east-1',
      profile: 'test',
      resourceId: 'test',
      domain: 'pub',
    } as AWSScannerCliArgsInterface)
  })

  it('should report OK', async () => {
    mock('EC2', 'describeInternetGateways', {
      InternetGateways: [
        {
          Attachments: [
            {
              State: 'test',
            },
          ],
        },
      ],
    })
    await handler({
      region: 'us-east-1',
      profile: 'test',
      resourceId: 'test',
      domain: 'pub',
    } as AWSScannerCliArgsInterface)
  })

  it('should report OK', async () => {
    mock('EC2', 'describeInternetGateways', {
      InternetGateways: [
        {
          Attachments: [{}],
        },
      ],
    })
    await handler({
      region: 'us-east-1',
      profile: 'test',
      resourceId: 'test',
      domain: 'pub',
    } as AWSScannerCliArgsInterface)
  })

  it('should report OK', async () => {
    mock('EC2', 'describeInternetGateways', {
      InternetGateways: [
        {
          Attachments: [],
        },
      ],
    })
    await handler({
      region: 'us-east-1',
      profile: 'test',
      resourceId: 'test',
      domain: 'pub',
    } as AWSScannerCliArgsInterface)
  })

  it('should report OK', async () => {
    mock('EC2', 'describeInternetGateways', {
      InternetGateways: [{}],
    })
    await handler({
      region: 'us-east-1',
      profile: 'test',
      resourceId: 'test',
      domain: 'pub',
    } as AWSScannerCliArgsInterface)
  })

  it('should report OK', async () => {
    mock('EC2', 'describeInternetGateways', {
      InternetGateways: [
        {
          Attachments: [],
        },
      ],
    })
    await handler({
      region: 'all',
      domain: 'pub',
    } as AWSScannerCliArgsInterface)
  })

  it('should report UNKNOWN', async () => {
    mock('EC2', 'describeInternetGateways', Promise.reject('test'))
    await handler({
      region: 'all',
      domain: 'pub',
    } as AWSScannerCliArgsInterface)
  })

  it('should report nothing', async () => {
    mock('EC2', 'describeInternetGateways', {})
    await handler({
      region: 'all',
      domain: 'pub',
    } as AWSScannerCliArgsInterface)
  })

  it('should report nothing', async () => {
    mock('EC2', 'describeInternetGateways', {})
    await handler({
      region: 'all',
      domain: 'gov',
    } as AWSScannerCliArgsInterface)
  })

  it('should report nothing', async () => {
    mock('EC2', 'describeInternetGateways', {})
    await handler({
      region: 'all',
      domain: 'test',
    } as AWSScannerCliArgsInterface)
  })

  it('should report nothing', async () => {
    mock('EC2', 'describeInternetGateways', {})
    await handler({
      region: 'us-east-1',
      domain: 'pub',
    } as AWSScannerCliArgsInterface)
  })

  it('should report nothing', async () => {
    mock('EC2', 'describeInternetGateways', {})
    await handler({
      region: 'us-gov-west-1',
      domain: 'gov',
    } as AWSScannerCliArgsInterface)
  })
})
