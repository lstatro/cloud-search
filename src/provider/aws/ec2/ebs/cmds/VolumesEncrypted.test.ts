import 'mocha'
import { mock, restore } from 'aws-sdk-mock'
import { SinonFakeTimers, useFakeTimers } from 'sinon'
import { handler } from './volumesEncrypted'
import { AWSScannerCliArgsInterface } from 'cloud-search'

/** none of these tests should throw */

describe('ebs volume encryption', () => {
  const now = new Date(0)
  let clock: SinonFakeTimers
  beforeEach(() => {
    clock = useFakeTimers(now)
    mock('EC2', 'describeRegions', { Regions: [{ RegionName: 'us-east-1' }] })
  })

  afterEach(() => {
    clock.restore()
    restore()
  })

  it('should return OK for AWS key encrypted volumes in a region', async () => {
    mock('EC2', 'describeVolumes', {
      Volumes: [
        {
          Encrypted: true,
        },
      ],
    })
    const audits = await handler({
      region: 'us-east-1',
      profile: 'test',
      domain: 'pub',
    } as AWSScannerCliArgsInterface)
    console.log(audits)
  })
})
